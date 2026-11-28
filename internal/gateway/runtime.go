// Package gateway composes signed service ingress with the owned QUIC transport.
package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/solodyagin/outgate/internal/registry"
	"github.com/solodyagin/outgate/internal/servicecall"
	"github.com/solodyagin/outgate/internal/transport/quictunnel"
)

var ErrClosed = errors.New("outgate: gateway runtime stopped or not serving")

type Config struct {
	Tunnel       quictunnel.SQLiteRuntimeConfig
	TunnelLimits quictunnel.RuntimeLimits
	// TLS identity, stores, routes, resolution and admission callbacks are owned
	// by this runtime and must be unset in Service/State. Other service settings
	// retain the signed listener semantics, including post-commit revalidation.
	Service     servicecall.Config
	State       servicecall.StateConfig
	Connections servicecall.ConnectionLimits
	MaxRequests int // bounds active HTTP handlers and external Ready probes
	// KeyHealth checks authoritative accepted-key source freshness, not merely
	// presence of a cached key. Successful assertions expire within five seconds.
	// All external callbacks must honor their context.
	KeyHealth func(context.Context) (time.Time, error)
}

// Runtime owns both ingress listeners and one pair of provisioned stores.
// Shutdown must be called even after Serve fails. GracefulShutdown coordinates
// HTTP completion and QUIC reconnect; Shutdown forces immediate cancellation.
// It does not initialize or repair state.
type Runtime struct {
	mu                             sync.Mutex
	tunnel                         tunnelOwner
	server                         *http.Server
	handler                        http.Handler
	connectionLimits               servicecall.ConnectionLimits
	maxRequests, active            int
	started, httpServing, stopping bool
	listener                       net.Listener
	packet                         net.PacketConn
	cancel                         context.CancelFunc
	handlers                       sync.WaitGroup
	serveDone, closed              chan struct{}
	stopOnce                       sync.Once
	forceOnce                      sync.Once
	force                          chan struct{}
	closeErr                       error
}

type tunnelOwner interface {
	Serve(net.PacketConn) error
	Ready(context.Context) error
	Stop()
	BeginDrain(time.Time) <-chan struct{}
	Shutdown(context.Context) error
}

func OpenSQLiteRuntime(ctx context.Context, config Config) (*Runtime, error) {
	s := config.Service
	if config.MaxRequests < 1 || config.MaxRequests > 1000000 || config.KeyHealth == nil ||
		config.Connections.MaxConnections < 1 || config.Connections.ConnectionsPerIP < 1 || config.Connections.ConnectionsPerIP > config.Connections.MaxConnections ||
		len(s.Certificate.Certificate) != 0 || s.Certificate.PrivateKey != nil || s.ClientRoots != nil || s.TrustDomain != "" ||
		s.Routes != nil || s.Replay != nil || s.ReplayNamespace != "" || s.Resolve != nil || s.Authenticate != nil || s.Authorize != nil || s.Revalidate != nil || config.State.Store != nil {
		return nil, servicecall.ErrConfig
	}
	prior := config.Tunnel.AdditionalSecurity
	config.Tunnel.AdditionalSecurity = func(ctx context.Context) (time.Time, error) {
		deadline, err := fresh(ctx, config.KeyHealth)
		if err != nil {
			return time.Time{}, err
		}
		if prior != nil {
			other, err := fresh(ctx, prior)
			if err != nil {
				return time.Time{}, err
			}
			if other.Before(deadline) {
				deadline = other
			}
		}
		return deadline, nil
	}
	tunnel, err := quictunnel.OpenSQLiteRuntime(ctx, config.Tunnel, config.TunnelLimits)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Runtime, error) { _ = tunnel.Shutdown(context.Background()); return nil, err }
	// Detach the DER chain as well as the CA pool; key material remains read-only.
	s.Certificate = tls.Certificate{PrivateKey: config.Tunnel.Certificate.PrivateKey}
	s.Certificate.Certificate = make([][]byte, len(config.Tunnel.Certificate.Certificate))
	for i, der := range config.Tunnel.Certificate.Certificate {
		s.Certificate.Certificate[i] = append([]byte(nil), der...)
	}
	s.Certificate.Leaf, err = x509.ParseCertificate(s.Certificate.Certificate[0])
	if err != nil {
		return fail(err)
	}
	s.ClientRoots = config.Tunnel.ClientRoots.Clone()
	s.TrustDomain = config.Tunnel.Admission.TrustDomain
	s.Routes, s.Replay, s.ReplayNamespace = tunnel.Routes(), tunnel.ReplayStore(), config.Tunnel.Replay.Namespace
	s.Resolve = exactResolver(tunnel.Session)
	config.State.Store = tunnel.ControlStore()
	s, err = servicecall.BindStateAdmission(s, config.State)
	if err != nil {
		return fail(err)
	}
	server, err := servicecall.NewServer(s)
	if err != nil {
		return fail(err)
	}
	server.TLSConfig.MaxVersion = server.TLSConfig.MinVersion
	server.TLSConfig.SessionTicketsDisabled = true
	return newRuntime(tunnel, server, config.Connections, config.MaxRequests), nil
}

func fresh(ctx context.Context, source func(context.Context) (time.Time, error)) (time.Time, error) {
	deadline, err := source(ctx)
	now := time.Now()
	if err != nil {
		return time.Time{}, err
	}
	if ctx.Err() != nil || !deadline.After(now) || deadline.After(now.Add(5*time.Second)) {
		return time.Time{}, ErrClosed
	}
	return deadline, nil
}

func exactResolver(resolve func(*registry.Session) (*quictunnel.BoundSession, error)) func(context.Context, registry.Decision) (servicecall.Recipient, error) {
	return func(ctx context.Context, route registry.Decision) (servicecall.Recipient, error) {
		if err := ctx.Err(); err != nil {
			return servicecall.Recipient{}, err
		}
		bound, err := resolve(route.Session)
		if err != nil {
			return servicecall.Recipient{}, err
		}
		if bound == nil || bound.Handle() != route.Session {
			return servicecall.Recipient{}, ErrClosed
		}
		return servicecall.Recipient{Transport: bound}, nil
	}
}

func newRuntime(tunnel tunnelOwner, server *http.Server, limits servicecall.ConnectionLimits, maxRequests int) *Runtime {
	ctx, cancel := context.WithCancel(context.Background())
	r := &Runtime{tunnel: tunnel, server: server, handler: server.Handler, maxRequests: maxRequests, cancel: cancel, serveDone: make(chan struct{}), closed: make(chan struct{}), force: make(chan struct{})}
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	server.Handler = http.HandlerFunc(r.serveHTTP)
	// Wrap when Serve receives the socket, rather than opening a listener here.
	r.connectionLimits = limits
	return r
}

func (r *Runtime) serveHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	if !r.started || r.stopping {
		r.mu.Unlock()
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.active >= r.maxRequests {
		r.mu.Unlock()
		http.Error(w, "busy", http.StatusTooManyRequests)
		return
	}
	r.active++
	r.handlers.Add(1)
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.active--; r.mu.Unlock(); r.handlers.Done() }()
	if err := r.ready(req.Context()); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	r.handler.ServeHTTP(w, req)
}

// Ready requires both listeners and the actual QUIC/control/replay/key health
// boundary. The real replay restart barrier is never bypassed for service calls.
func (r *Runtime) Ready(ctx context.Context) error {
	r.mu.Lock()
	if !r.started || r.stopping || r.active >= r.maxRequests {
		r.mu.Unlock()
		return ErrClosed
	}
	r.active++
	r.handlers.Add(1)
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.active--; r.mu.Unlock(); r.handlers.Done() }()
	return r.ready(ctx)
}

func (r *Runtime) ready(ctx context.Context) error {
	r.mu.Lock()
	serving := r.started && r.httpServing && !r.stopping
	r.mu.Unlock()
	if !serving {
		return ErrClosed
	}
	if err := r.tunnel.Ready(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	stopped := r.stopping || !r.httpServing
	r.mu.Unlock()
	if stopped {
		return ErrClosed
	}
	return nil
}

// Serve takes both sockets on the first valid invocation. Either listener's
// termination stops the whole runtime. Subsequent/rejected calls retain caller
// ownership. TCP quotas apply before TLS; QUIC has its own bounded reservations.
func (r *Runtime) Serve(listener net.Listener, packet net.PacketConn) error {
	if listener == nil || packet == nil {
		return servicecall.ErrConfig
	}
	limited, err := servicecall.LimitListener(listener, r.connectionLimits)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if r.started || r.stopping {
		r.mu.Unlock()
		return ErrClosed
	}
	r.started = true
	r.listener = limited
	r.packet = packet
	r.mu.Unlock()
	type serveResult struct {
		err  error
		http bool
	}
	results := make(chan serveResult, 2)
	go func() {
		results <- serveResult{r.server.ServeTLS(&servingListener{Listener: limited, runtime: r}, "", ""), true}
	}()
	go func() { results <- serveResult{r.tunnel.Serve(packet), false} }()
	var first, failure error
	for i := 0; i < 2; i++ {
		result := <-results
		if i == 0 {
			first = result.err
		}
		r.mu.Lock()
		intentional := r.stopping && (result.http && errors.Is(result.err, http.ErrServerClosed) || !result.http && errors.Is(result.err, quictunnel.ErrRuntimeClosed))
		r.mu.Unlock()
		if !intentional {
			if failure == nil {
				failure = result.err
			}
			r.stop()
		}
	}

	close(r.serveDone)
	if failure != nil {
		return failure
	}
	return first
}

func (r *Runtime) stop() {
	r.forceOnce.Do(func() { close(r.force) })
	r.beginShutdown(false, time.Time{})
	r.cancel()
	r.tunnel.Stop()
}

func (r *Runtime) beginShutdown(graceful bool, deadline time.Time) {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		r.stopping = true
		started, listener := r.started, r.listener
		r.mu.Unlock()
		handlersDone := make(chan struct{})
		go func() { r.handlers.Wait(); close(handlersDone) }()
		var grace context.Context
		var cancel context.CancelFunc
		var tunnelDone <-chan struct{}
		httpDone := make(chan struct{})
		if graceful {
			limit := time.Now().Add(30 * time.Second)
			if deadline.IsZero() || deadline.After(limit) {
				deadline = limit
			}
			grace, cancel = context.WithDeadline(context.Background(), deadline)
			tunnelDone = r.tunnel.BeginDrain(deadline)
			go func() { _ = r.server.Shutdown(grace); close(httpDone) }()
		}
		go func() {
			if graceful {
				// Each channel is observed once. A slow session cannot give another
				// listener or handler a fresh budget, and abort does not wait on callbacks.
				for tunnelDone != nil || httpDone != nil || handlersDone != nil {
					select {
					case <-tunnelDone:
						tunnelDone = nil
					case <-httpDone:
						httpDone = nil
					case <-handlersDone:
						handlersDone = nil
					case <-grace.Done():
						goto force
					case <-r.force:
						goto force
					}
				}
			}
		force:
			if cancel != nil {
				cancel()
			}
			r.cancel()
			r.tunnel.Stop()
			_ = r.server.Close()
			if listener != nil {
				_ = listener.Close()
			}
			if started {
				<-r.serveDone
			}
			r.handlers.Wait()
			r.closeErr = r.tunnel.Shutdown(context.Background())
			if r.packet != nil {
				_ = r.packet.Close()
			}
			close(r.closed)
		}()
	})
}

// GracefulShutdown rejects new work immediately, then gives HTTP handlers and
// QUIC reconnect handshakes one shared budget: the earlier of ctx's deadline and
// 30 seconds. Context cancellation or Shutdown aborts the grace period. Stores
// remain owned through actual cleanup even if this caller stops waiting. The
// first graceful call fixes the maximum budget; later calls cannot extend it.
func (r *Runtime) GracefulShutdown(ctx context.Context) error {
	deadline, _ := ctx.Deadline()
	r.beginShutdown(true, deadline)
	select {
	case <-r.closed:
		return r.closeErr
	default:
	}
	select {
	case <-r.closed:
		return r.closeErr
	case <-ctx.Done():
		r.stop()
		return ctx.Err()
	}
}

// Shutdown cancels ingress immediately, then retains shared stores until all
// HTTP handlers and native owners have actually returned. Caller timeout never
// releases ownership; background cleanup continues and may be awaited again.
func (r *Runtime) Shutdown(ctx context.Context) error {
	r.stop()
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

// Accept is reached only after ServeTLS has validated its static configuration.
// Mark a failed listener unavailable before the Serve goroutine reports it.
type servingListener struct {
	net.Listener
	runtime *Runtime
}

func (l *servingListener) Accept() (net.Conn, error) {
	l.runtime.mu.Lock()
	l.runtime.httpServing = !l.runtime.stopping
	l.runtime.mu.Unlock()
	conn, err := l.Listener.Accept()
	if err != nil {
		l.runtime.mu.Lock()
		l.runtime.httpServing = false
		l.runtime.mu.Unlock()
	}
	return conn, err
}
