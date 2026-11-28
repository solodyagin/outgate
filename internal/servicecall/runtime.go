package servicecall

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/solodyagin/outgate-sdk/replay"
	"github.com/solodyagin/outgate/internal/resourcebudget"
)

// ConnectionLimits bound accepted TCP connections before TLS allocates state.
// Local quotas apply alongside an optional shared connection/byte pool. Other
// listeners participate only when their owner installs the same shared pool.
type ConnectionLimits struct {
	MaxConnections   int
	ConnectionsPerIP int
	Shared           *resourcebudget.Budget
	ConnectionBytes  int64 // positive operator-provided TLS/HTTP reservation when Shared is set
}

// SQLiteRuntime owns a dedicated HTTPS server and its provisioned replay store.
// It does not supply grant/policy/revocation sources or initialize missing state.
// Call Shutdown even when Serve returns an error.
type SQLiteRuntime struct {
	server    *http.Server
	store     io.Closer
	limits    ConnectionLimits
	started   atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

func OpenSQLiteRuntime(ctx context.Context, config Config, storage replay.SQLiteConfig, limits ConnectionLimits) (*SQLiteRuntime, error) {
	if !validConnectionLimits(limits) {
		return nil, ErrConfig
	}
	server, store, err := OpenSQLiteServer(ctx, config, storage)
	if err != nil {
		return nil, err
	}
	return &SQLiteRuntime{server: server, store: store, limits: limits}, nil
}

// Serve takes ownership of a plain TCP listener on its first invocation. Only
// mTLS is served, using the validated server configuration. Excess connections
// are closed before handshaking, without allocating an unbounded waiting queue.
// Serve returns http.ErrServerClosed after successful shutdown.
func (r *SQLiteRuntime) Serve(listener net.Listener) error {
	if listener == nil || !r.started.CompareAndSwap(false, true) {
		return ErrConfig
	}
	limited, err := LimitListener(listener, r.limits)
	if err != nil {
		return err
	}
	return r.server.ServeTLS(limited, "", "")
}

// Shutdown stops admission and waits for active HTTP handlers before closing
// SQLite. If ctx expires, the store remains open and Shutdown may be retried;
// closing durable state underneath a still-running handler is never safe.
func (r *SQLiteRuntime) Shutdown(ctx context.Context) error {
	if err := r.server.Shutdown(ctx); err != nil {
		return err
	}
	r.closeOnce.Do(func() { r.closeErr = r.store.Close() })
	return r.closeErr
}

// LimitListener applies the same pre-TLS quotas to a listener owned by a shared
// runtime. On error ownership stays with the caller. Closing the returned
// listener closes the underlying listener; accepted connections release their
// reservations only when closed.
func LimitListener(listener net.Listener, limits ConnectionLimits) (net.Listener, error) {
	if listener == nil || !validConnectionLimits(limits) {
		return nil, ErrConfig
	}
	return &quotaListener{Listener: listener, limits: limits, peers: make(map[netip.Addr]int)}, nil
}

type quotaListener struct {
	net.Listener
	mu     sync.Mutex
	limits ConnectionLimits
	total  int
	peers  map[netip.Addr]int
}

func (l *quotaListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		peer, parseErr := netip.ParseAddr(host)
		if err != nil || parseErr != nil || peer.Zone() != "" {
			_ = conn.Close()
			continue
		}
		peer = peer.Unmap()
		l.mu.Lock()
		allowed := l.total < l.limits.MaxConnections && l.peers[peer] < l.limits.ConnectionsPerIP
		var reservation *resourcebudget.Lease
		if allowed && l.limits.Shared != nil {
			var err error
			reservation, err = l.limits.Shared.Acquire(peer, l.limits.ConnectionBytes)
			allowed = err == nil
		}
		if allowed {
			l.total++
			l.peers[peer]++
		}
		l.mu.Unlock()
		if !allowed {
			_ = conn.Close()
			continue
		}
		return &quotaConn{Conn: conn, release: func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			reservation.Release()
			l.total--
			l.peers[peer]--
			if l.peers[peer] == 0 {
				delete(l.peers, peer)
			}
		}}, nil
	}
}

type quotaConn struct {
	net.Conn
	once     sync.Once
	release  func()
	closeErr error
}

func (c *quotaConn) Close() error {
	c.once.Do(func() { c.closeErr = c.Conn.Close(); c.release() })
	return c.closeErr
}

func validConnectionLimits(l ConnectionLimits) bool {
	if l.MaxConnections < 1 || l.ConnectionsPerIP < 1 || l.ConnectionsPerIP > l.MaxConnections {
		return false
	}
	if l.Shared == nil {
		return l.ConnectionBytes == 0
	}
	return l.ConnectionBytes <= 1<<30 && l.Shared.CanFit(l.ConnectionBytes)
}
