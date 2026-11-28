package quictunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate/internal/registry"
)

var ErrControlNotIntegrated = errors.New("outgate: QUIC quiescent-fence capability not negotiated")

// Binding is supplied only after external identity/grant/permissions/conflicts
// and required durable commit/outbox checks. Session is a fresh registration
// created by that admission transaction. SecurityReady is an explicit verified
// local security-store assertion, default false. No production RAM fallback is
// supplied here. An admission callback must clean up its own failed transaction.
type Binding struct {
	Release          func() // releases admission ownership after actual local cleanup
	Session          *registry.Session
	Ack              v1.RegisterAck
	SecurityReady    bool
	SecurityDeadline time.Time
	// RenewSecurity opts into a separately renewable freshness lease. Nil retains
	// the legacy non-extending SetSecurity deadline behavior.
	RenewSecurity func(context.Context) (SecurityLease, error)
	Renewal       SecurityRenewal
}
type Admit func(context.Context, tls.ConnectionState, []byte, v1.Register) (Binding, error)

type BoundOptions struct {
	Transport    quiccontrol.Options
	TickInterval time.Duration // default 100ms; must not exceed 1s
	MaxCommands  int           // default 64, bounded prepaid session command history
}

// BoundSession owns status receipt, freshness/security timers, readiness and
// local native exchange cleanup for one registry registration. Per-request
// authorization and route selection must precede RoundTrip. Graceful drain and
// unregister require negotiated minor-1 quiescent fences; legacy control closes
// fail-closed rather than inventing cross-stream ordering guarantees.
type BoundSession struct {
	mu             sync.Mutex
	expiryMu       sync.Mutex
	expiryTimer    *time.Timer
	expiryDeadline time.Time
	expiryHard     time.Time
	expiryLease    time.Time
	expiryFired    bool
	model          *sessionstate.State
	routes         *registry.Registry
	handle         *registry.Session
	raw            *Session
	conn           *quic.Conn
	ctx            context.Context
	cancel         context.CancelFunc
	interval       time.Duration
	closing        bool
	enabled        bool
	cause          error
	release        func()
	stopOnce       sync.Once
	closeOnce      sync.Once
	requests       sync.WaitGroup
	done           chan struct{}
	readerDone     chan struct{}
	timerDone      chan struct{}
	renewalDone    chan struct{}
	timerWake      chan struct{}
	writerDone     chan struct{}
	wake           chan struct{}
	pending        []nativeControl
	maxCommands    int
	fenceCap       bool
	paused         bool
	localDrain     bool
	excluded       bool
	terminalWrite  bool
	peerDrain      bool
	localDrainSent bool
	graceful       bool
	watermark      uint64
}

func AcceptBound(ctx context.Context, conn *quic.Conn, routes *registry.Registry, options BoundOptions, admit Admit) (*BoundSession, error) {
	if routes == nil || admit == nil {
		return nil, v1.ErrProtocol
	}
	if options.TickInterval == 0 {
		options.TickInterval = 100 * time.Millisecond
	}
	if options.TickInterval <= 0 || options.TickInterval > time.Second {
		return nil, v1.ErrProtocol
	}
	if options.MaxCommands == 0 {
		options.MaxCommands = 64
	}
	registrationTimeout := options.Transport.RegisterTimeout
	if registrationTimeout == 0 {
		registrationTimeout = 10 * time.Second
	}
	model, err := sessionstate.New(sessionstate.Config{Local: sessionstate.Gateway, Development: options.Transport.Development, NativeStreams: true, MaxControlBytes: v1.MaxControlBytes, RegisterTimeout: registrationTimeout, MaxCommands: options.MaxCommands})
	if err != nil {
		return nil, err
	}
	var handle *registry.Session
	owned := false
	var release func()
	fenceCap := false
	var renew func(context.Context) (SecurityLease, error)
	var renewal SecurityRenewal
	var securityDeadline time.Time
	var credentialDeadline time.Time
	raw, err := Accept(ctx, conn, options.Transport, func(ctx context.Context, peer tls.ConnectionState, credential []byte, reg v1.Register) (v1.RegisterAck, error) {
		now := time.Now()
		if err := model.Begin(now); err != nil {
			return v1.RegisterAck{}, err
		}
		if _, err := model.Apply(sessionstate.Service, reg, now); err != nil {
			return v1.RegisterAck{}, err
		}
		b, _ := json.Marshal(reg)
		original, _ := v1.DecodeRegister(b)
		binding, err := admit(ctx, peer, credential, reg)
		release = binding.Release
		if err != nil {
			return v1.RegisterAck{}, err
		}
		snapshot, err := routes.BindTransport(binding.Session, original, registry.QUIC)
		if err != nil {
			return v1.RegisterAck{}, err
		}
		handle = binding.Session
		owned = true
		ack := binding.Ack
		if ack.RouteRevision != v1.U64(snapshot.RouteRevision) || len(ack.Paths) != len(snapshot.Paths) {
			return v1.RegisterAck{}, v1.ErrProtocol
		}
		for _, p := range ack.Paths {
			if string(snapshot.Paths[p.Path]) != p.State {
				return v1.RegisterAck{}, v1.ErrProtocol
			}
		}
		now = time.Now()
		if _, err = model.AuthorizeRegistration(now); err != nil {
			return v1.RegisterAck{}, err
		}
		if _, err = model.Apply(sessionstate.Gateway, ack, now); err != nil {
			return v1.RegisterAck{}, err
		}
		if binding.RenewSecurity != nil {
			renewal, err = binding.Renewal.normalized()
			if err != nil {
				return v1.RegisterAck{}, err
			}
			_, err = model.RenewSecurity(binding.SecurityReady, binding.SecurityDeadline, now)
		} else {
			_, err = model.Security(binding.SecurityReady, binding.SecurityDeadline, now)
		}
		if err != nil {
			return v1.RegisterAck{}, err
		}
		renew, securityDeadline = binding.RenewSecurity, binding.SecurityDeadline
		if ack.CredentialExpiresAt != nil {
			credentialDeadline = time.Unix(*ack.CredentialExpiresAt, 0)
		}
		fenceCap = v1.HasQUICQuiescentFence(ack)
		return ack, nil
	})
	if err != nil {
		if owned {
			_ = routes.SetReady(handle, false)
			_ = routes.Disconnect(handle)
		}
		if release != nil {
			_ = conn.CloseWithError(quiccontrol.CodeProtocol, "admission_failed")
			release()
		}
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	s := &BoundSession{model: model, routes: routes, handle: handle, raw: raw, conn: conn, ctx: lifetime, cancel: cancel, interval: options.TickInterval, done: make(chan struct{}), readerDone: make(chan struct{}), timerDone: make(chan struct{})}
	s.release = release
	s.fenceCap = fenceCap
	s.maxCommands = options.MaxCommands
	s.renewalDone = make(chan struct{})
	s.timerWake = make(chan struct{}, 1)
	s.pending = make([]nativeControl, 0, options.MaxCommands)
	s.wake = make(chan struct{}, 1)
	s.writerDone = make(chan struct{})
	_ = s.armExpiry(credentialDeadline, false)
	_ = s.armExpiry(securityDeadline, renew != nil)
	go s.readLoop()
	go s.timerLoop()
	go s.writerLoop()
	go s.renewalLoop(renew, renewal, securityDeadline)
	return s, nil
}

func (s *BoundSession) Handle() *registry.Session { return s.handle }
func (s *BoundSession) Done() <-chan struct{}     { return s.done }
func (s *BoundSession) Err() error                { s.mu.Lock(); defer s.mu.Unlock(); return s.cause }
func (s *BoundSession) Snapshot() sessionstate.Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.model.Snapshot()
}

func (s *BoundSession) syncReadyLocked() error {
	if s.excluded {
		return nil
	}
	return s.routes.SetReady(s.handle, s.enabled && !s.closing && s.model.Snapshot().Phase == sessionstate.Ready)
}

// EnableDispatch is called only after the owner has published the handle to
// transport mapping. An immediately arriving ready status must not expose a
// registry handle before the router can find its BoundSession. This does not
// activate pending routes or bypass freshness/security gates.
func (s *BoundSession) EnableDispatch() error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return sessionstate.ErrState
	}
	effect, err := s.model.Advance(time.Now())
	if err == nil {
		s.enabled = true
		err = s.syncReadyLocked()
	}
	s.mu.Unlock()
	if err != nil || effect.CloseTransport {
		s.stop(err)
	}
	return err
}

func (s *BoundSession) readLoop() {
	defer close(s.readerDone)
	for {
		message, err := s.raw.Receive(s.ctx)
		if err != nil {
			s.stop(err)
			return
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			return
		}
		effect, err, terminal := s.receiveLocked(message)
		if err == nil {
			err = s.syncReadyLocked()
		}
		s.mu.Unlock()
		if err != nil || effect.CloseTransport {
			s.stop(err)
			return
		}
		s.signalWriter()
		if terminal {
			return
		}
	}
}
func (s *BoundSession) timerLoop() {
	defer close(s.timerDone)
	timer := time.NewTimer(time.Nanosecond)
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.timerWake:
		case <-timer.C:
		}
		s.mu.Lock()
		if s.closing {
			s.mu.Unlock()
			return
		}
		if s.terminalWrite {
			s.mu.Unlock()
			timer.Reset(s.interval)
			continue
		}
		effect, err := s.model.Advance(time.Now())
		if err == nil {
			err = s.syncReadyLocked()
		}
		delay := s.interval
		if deadline := s.model.Snapshot().Deadline; !deadline.IsZero() {
			delay = min(delay, max(time.Nanosecond, time.Until(deadline)))
		}
		s.mu.Unlock()
		if err != nil || effect.CloseTransport {
			s.stop(err)
			return
		}
		timer.Reset(delay)
	}
}

func (s *BoundSession) SetSecurity(ready bool, deadline time.Time) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return sessionstate.ErrState
	}
	effect, err := s.model.Security(ready, deadline, time.Now())
	if err == nil {
		err = s.armExpiry(deadline, false)
	}
	if err == nil {
		err = s.syncReadyLocked()
	}
	s.mu.Unlock()
	s.signalTimer()
	if err != nil || effect.CloseTransport {
		s.stop(err)
	}
	return err
}
func (s *BoundSession) Revoke() { s.stop(sessionstate.ErrSecurity) }

func (s *BoundSession) RoundTrip(req *http.Request) (*http.Response, error) {
	fail := func(err error) (*http.Response, error) {
		if req != nil && req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	if req == nil {
		return fail(v1.ErrProtocol)
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return fail(sessionstate.ErrState)
	}
	lease, effect, err := s.model.AdmitNative(time.Now())
	syncErr := s.syncReadyLocked()
	if err == nil {
		err = syncErr
	}
	if err == nil {
		err = s.routes.CanDispatch(s.handle)
	}
	if err != nil {
		if lease != nil {
			_, _ = s.model.CompleteNative(lease, time.Now())
		}
		s.mu.Unlock()
		if effect.CloseTransport || syncErr != nil {
			s.stop(err)
		}
		return fail(err)
	}
	s.requests.Add(1)
	s.mu.Unlock()
	return s.raw.requests.RoundTripWithCompletion(req, func() {
		s.mu.Lock()
		effect, err := s.model.CompleteNative(lease, time.Now())
		s.requests.Done()
		s.mu.Unlock()
		if err != nil || effect.CloseTransport {
			s.stop(err)
		} else {
			s.signalWriter()
		}
	})
}

// Close cancels immediately and waits for local cleanup, bounded by ctx. An
// upload reader violating net/http's concurrent Close contract retains the old
// registration and blocks replacement; it never silently enables a new session.
func (s *BoundSession) Close(ctx context.Context) error {
	// Exactly one stop request can wait behind local lifecycle/registry locks.
	// Native cancellation and the caller's timeout do not wait for those locks.
	s.closeOnce.Do(func() {
		s.cancel()
		go func() { _ = s.conn.CloseWithError(quiccontrol.CodeNormal, "normal"); s.stop(context.Canceled) }()
	})
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *BoundSession) stop(cause error) {
	s.stopOnce.Do(func() {
		if cause == nil {
			cause = sessionstate.ErrState
		}
		s.mu.Lock()
		s.expiryMu.Lock()
		if s.expiryFired {
			cause = sessionstate.ErrSecurity
		}
		s.expiryMu.Unlock()
		snapshot := s.model.Snapshot()
		// After the terminal ack, the model's remaining deadline is security/
		// credential expiry (drain deadlines were consumed by finish). It must
		// still preempt a normal close while the carrier is alive.
		if !snapshot.TransportActive && !snapshot.Deadline.IsZero() && !time.Now().Before(snapshot.Deadline) {
			cause = sessionstate.ErrSecurity
		}
		s.closing = true
		s.cause = cause
		if errors.Is(cause, sessionstate.ErrSecurity) {
			s.graceful = false
			_, _ = s.model.Revoke(time.Now())
		} else if snapshot.TransportActive {
			_, _ = s.model.Disconnected(false, time.Now())
		}
		if errors.Is(cause, sessionstate.ErrSecurity) {
			_ = s.conn.CloseWithError(quiccontrol.CodeCredentialRevoked, "credential_revoked")
			s.cancel()
		}
		_ = s.routes.SetReady(s.handle, false)
		_ = s.routes.Drain(s.handle)
		s.mu.Unlock()
		s.cancel()
		go s.cleanup(cause)
	})
}
func (s *BoundSession) cleanup(cause error) {
	if errors.Is(cause, sessionstate.ErrSecurity) {
		_ = s.conn.CloseWithError(0x4f47540b, "credential_revoked")
	} else if !errors.Is(cause, context.Canceled) {
		_ = s.conn.CloseWithError(quiccontrol.CodeProtocol, "protocol_error")
	}
	_ = s.raw.Close()
	s.requests.Wait()
	<-s.readerDone
	<-s.timerDone
	<-s.writerDone
	<-s.renewalDone
	s.stopExpiry()
	s.mu.Lock()
	_ = s.routes.Disconnect(s.handle)
	if err := s.model.Cleaned(time.Now()); err != nil {
		s.cause = err
	}
	s.mu.Unlock()
	if s.release != nil {
		s.release()
	}
	close(s.done)
}
