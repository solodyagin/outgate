package quictunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/solodyagin/outgate-sdk/replay"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/peeridentity"
	"github.com/solodyagin/outgate/internal/registry"
)

var ErrRuntimeClosed = errors.New("outgate: QUIC runtime closed")

// SQLiteRuntime owns one QUIC listener, its admission/controller, exact handle
// map and already provisioned control/replay stores. Shutdown must be called
// even after Serve fails. It never bootstraps, repairs or activates routes.
type SQLiteRuntime struct {
	mu                                          sync.Mutex
	limits                                      RuntimeLimits
	charge                                      int64
	tls                                         *tls.Config
	quic                                        *quic.Config
	control                                     *controlstate.Store
	replay                                      *replay.SQLite
	owner                                       *controlstate.RegistrationOwner
	admission                                   *DurableAdmission
	ctx                                         context.Context
	cancel                                      context.CancelFunc
	started, serveEnded, stopping, networkEnded bool
	transport                                   *quic.Transport
	listener                                    *quic.Listener
	packet                                      net.PacketConn
	peers                                       map[netip.Addr]runtimePeer
	services                                    map[string]int64
	tickets                                     map[*runtimeTicket]struct{}
	sessions                                    map[*registry.Session]*BoundSession
	handshakes                                  int
	reserved                                    int64
	stopOnce, storesOnce, drainedOnce           sync.Once
	drained, closed                             chan struct{}
	closeErr                                    error
}

func OpenSQLiteRuntime(ctx context.Context, config SQLiteRuntimeConfig, limits RuntimeLimits) (*SQLiteRuntime, error) {
	if config.Admission.Owner != nil || config.Admission.Security != nil {
		return nil, controlstate.ErrConfig
	}
	tlsConfig, err := runtimeTLS(config.Certificate, config.ClientRoots)
	if err != nil {
		return nil, err
	}
	quicConfig, charge, err := runtimeTransport(limits, config.Admission.Policy)
	if err != nil {
		return nil, err
	}
	store, err := controlstate.Open(ctx, config.Control)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*SQLiteRuntime, error) { _ = store.Close(); return nil, err }
	owner, err := controlstate.OpenRegistrationOwner(ctx, store, config.Registry, config.MinimumControlRevision)
	if err != nil {
		return fail(err)
	}
	replayStore, err := replay.OpenSQLite(ctx, config.Replay)
	if err != nil {
		return fail(err)
	}
	source, err := SQLiteAdmissionSecurity(store, replayStore)
	if err != nil {
		_ = replayStore.Close()
		return fail(err)
	}
	config.Admission.Owner = owner
	additional := config.AdditionalSecurity
	config.Admission.Security = func(ctx context.Context) (AdmissionSecurity, error) {
		state, err := source(ctx)
		if err != nil {
			return AdmissionSecurity{}, err
		}
		state.ValidUntil = minTime(state.ValidUntil, tlsConfig.Certificates[0].Leaf.NotAfter)
		if additional != nil {
			deadline, err := additional(ctx)
			now := time.Now()
			if err != nil {
				return AdmissionSecurity{}, err
			}
			if !deadline.After(now) || deadline.After(now.Add(5*time.Second)) {
				return AdmissionSecurity{}, controlstate.ErrUnavailable
			}
			state.ValidUntil = minTime(state.ValidUntil, deadline)
		}
		if ctx.Err() != nil || !state.ValidUntil.After(time.Now()) {
			return AdmissionSecurity{}, controlstate.ErrUnavailable
		}
		return state, nil
	}
	admission, err := NewDurableAdmission(config.Admission)
	if err != nil {
		_ = replayStore.Close()
		return fail(err)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	r := &SQLiteRuntime{limits: limits, charge: charge, tls: tlsConfig, quic: quicConfig, control: store, replay: replayStore, owner: owner, admission: admission, ctx: lifetime, cancel: cancel, peers: make(map[netip.Addr]runtimePeer), services: make(map[string]int64), tickets: make(map[*runtimeTicket]struct{}), sessions: make(map[*registry.Session]*BoundSession), drained: make(chan struct{}), closed: make(chan struct{})}
	for _, id := range owner.ServiceIDs() {
		r.services[id] = 0
	}
	return r, nil
}

// Serve takes exclusive ownership of the supplied UDP socket on its first call.
// Stateless Retry validates the source before bounded pre-TLS allocation. Full
// TLS 1.3 mTLS completes before the existing durable registration pipeline runs.
func (r *SQLiteRuntime) Serve(packet net.PacketConn) error {
	if packet == nil {
		return controlstate.ErrConfig
	}
	r.mu.Lock()
	if r.started || r.stopping {
		r.mu.Unlock()
		return ErrRuntimeClosed
	}
	r.started = true
	r.packet = packet
	transport := &quic.Transport{Conn: packet, VerifySourceAddress: func(net.Addr) bool { return true }, ConnContext: r.connectionContext}
	r.transport = transport
	r.mu.Unlock()
	defer func() { r.beginStop(); r.mu.Lock(); r.serveEnded = true; r.maybeDrainedLocked(); r.mu.Unlock() }()
	listener, err := transport.Listen(r.tls, r.quic)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.listener = listener
	stopping := r.stopping
	r.mu.Unlock()
	if stopping {
		_ = listener.Close()
		return ErrRuntimeClosed
	}
	for {
		conn, err := listener.Accept(r.ctx)
		if err != nil {
			r.mu.Lock()
			stopping := r.stopping
			r.mu.Unlock()
			if stopping {
				return ErrRuntimeClosed
			}
			return err
		}
		ticket := r.attach(conn)
		if ticket == nil {
			_ = conn.CloseWithError(quiccontrol.CodeNormal, "server_shutdown")
			continue
		}
		go r.handle(conn, ticket)
	}
}

func (r *SQLiteRuntime) handle(conn *quic.Conn, ticket *runtimeTicket) {
	defer func() { r.mu.Lock(); r.releaseLocked(ticket); r.mu.Unlock() }()
	bound, err := r.admission.accept(r.ctx, conn, func(state tls.ConnectionState) error {
		peer, ok := peeridentity.Read(&state, r.admission.config.TrustDomain, time.Now())
		if !ok {
			return controlstate.ErrDenied
		}
		return r.bindService(ticket, peer.ServiceID)
	})
	if err != nil {
		_ = conn.CloseWithError(quiccontrol.CodeProtocol, "admission_refused")
		return
	}
	r.mu.Lock()
	stopping := r.stopping
	if !stopping {
		r.sessions[bound.Handle()] = bound
	}
	r.mu.Unlock()
	if stopping || bound.EnableDispatch() != nil {
		_ = bound.Close(context.Background())
	} else {
		<-bound.Done()
	}
	r.mu.Lock()
	if r.sessions[bound.Handle()] == bound {
		delete(r.sessions, bound.Handle())
	}
	r.mu.Unlock()
}

// Session resolves only the exact currently published handle; it never selects
// an instance by reusable ID or retries a request. Routing/authz remain external.
func (r *SQLiteRuntime) Session(handle *registry.Session) (*BoundSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	bound := r.sessions[handle]
	if r.stopping || bound == nil {
		return nil, ErrRuntimeClosed
	}
	select {
	case <-bound.Done():
		return nil, ErrRuntimeClosed
	default:
		return bound, nil
	}
}

func (r *SQLiteRuntime) Routes() *registry.Registry { return r.owner.Routes() }

// ControlStore/ReplayStore may be used by other runtime components; only this
// runtime closes them, after its sessions and callbacks actually finish.
// Other registration transports must use a future shared lifecycle owner, not
// acquire independent leases behind this runtime's connection accounting.
func (r *SQLiteRuntime) ControlStore() *controlstate.Store { return r.control }
func (r *SQLiteRuntime) ReplayStore() *replay.SQLite       { return r.replay }

// Ready checks only this runtime's listener/control/replay/publication boundary.
// A healthy warming replay store still returns not-ready; it permits registration.
func (r *SQLiteRuntime) Ready(ctx context.Context) error {
	r.mu.Lock()
	serving := r.listener != nil && !r.stopping
	r.mu.Unlock()
	if !serving {
		return ErrRuntimeClosed
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := r.owner.Routes().CheckPublication(); err != nil {
		return err
	}
	if _, err := r.admission.security(ctx); err != nil {
		return err
	}
	if err := r.replay.Ready(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	stopped := r.stopping
	r.mu.Unlock()
	if stopped {
		return ErrRuntimeClosed
	}
	return nil
}

type RuntimeStats struct {
	Connections, Handshakes, Sessions int
	ReservedBytes                     int64
	Stopping                          bool
}

func (r *SQLiteRuntime) Stats() RuntimeStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RuntimeStats{len(r.tickets), r.handshakes, len(r.sessions), r.reserved, r.stopping}
}

// Stop immediately disables admission/resolution and starts network cleanup,
// without closing shared stores. A composing runtime must wait for its own
// users of ControlStore/ReplayStore before calling Shutdown to release them.
// Stop is nonblocking and idempotent; Shutdown is still required.
func (r *SQLiteRuntime) Stop() { r.beginStop() }

func (r *SQLiteRuntime) beginStop() {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		r.stopping = true
		transport, packet := r.transport, r.packet
		conns := make([]*quic.Conn, 0, len(r.tickets))
		for ticket := range r.tickets {
			if ticket.conn != nil {
				conns = append(conns, ticket.conn)
			}
		}
		r.mu.Unlock()
		r.cancel()
		go func() {
			// Send normal close while the UDP socket can still transmit. Transport.Close
			// also cancels unaccepted/failed handshakes, but destroys connections silently.
			var closing sync.WaitGroup
			for _, conn := range conns {
				closing.Go(func() { _ = conn.CloseWithError(quiccontrol.CodeNormal, "server_shutdown") })
			}
			closing.Wait()
			if transport != nil {
				_ = transport.Close()
			}
			if packet != nil {
				_ = packet.Close()
			}
			r.mu.Lock()
			r.networkEnded = true
			r.maybeDrainedLocked()
			r.mu.Unlock()
		}()
	})
}

func (r *SQLiteRuntime) maybeDrainedLocked() {
	if r.stopping && r.networkEnded && (!r.started || r.serveEnded) && len(r.tickets) == 0 {
		r.drainedOnce.Do(func() { close(r.drained) })
	}
}

// Shutdown stops admission immediately. Context expiry leaves stores owned until
// every handshake, registration, native exchange and checker has actually ended;
// completion continues in the background and callers may wait again. Closing a
// listener or losing a network connection alone never releases a live ticket.
func (r *SQLiteRuntime) Shutdown(ctx context.Context) error {
	r.beginStop()
	r.storesOnce.Do(func() {
		go func() { <-r.drained; r.closeErr = errors.Join(r.replay.Close(), r.control.Close()); close(r.closed) }()
	})
	select {
	case <-r.closed:
		return r.closeErr
	default:
	}
	select {
	case <-r.closed:
		return r.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
