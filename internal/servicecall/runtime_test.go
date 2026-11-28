package servicecall

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate-sdk/replay"
)

type closeRecorder struct{ calls atomic.Int32 }

func (c *closeRecorder) Close() error { c.calls.Add(1); return nil }

func TestSQLiteRuntimeShutdownKeepsStoreUntilHandlersFinish(t *testing.T) {
	f := testFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	original := f.config.Authenticate
	f.config.Authenticate = func(ctx context.Context, peer Peer, grant, key string) (delivery.Key, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return delivery.Key{}, ctx.Err()
		}
		return original(ctx, peer, grant, key)
	}
	configured, err := NewServer(f.config)
	must(t, err)
	closed := &closeRecorder{}
	runtime := &SQLiteRuntime{server: configured, store: closed, limits: ConnectionLimits{MaxConnections: 2, ConnectionsPerIP: 1}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	serving := make(chan error, 1)
	go func() { serving <- runtime.Serve(listener) }()
	t.Cleanup(func() { unblock(); _ = runtime.Shutdown(context.Background()) })
	transport := &http.Transport{TLSClientConfig: f.clientTLS}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	result := make(chan error, 1)
	request := signedRequest(t, "https://"+listener.Addr().String(), publicURI, callerID, 0, f.call)
	go func() {
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode != 200 {
				err = errors.New("in-flight request failed")
			}
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach admission")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := runtime.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error %v", err)
	}
	if closed.calls.Load() != 0 {
		t.Fatal("closed replay store under active handler")
	}
	unblock()
	must(t, <-result)
	must(t, runtime.Shutdown(t.Context()))
	must(t, runtime.Shutdown(t.Context()))
	if closed.calls.Load() != 1 {
		t.Fatal("store not closed exactly once")
	}
	if err := <-serving; !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}

func TestSQLiteRuntimeUsesProvisionedStateAndRecoveryBarrier(t *testing.T) {
	f := testFixture(t)
	f.config.Replay, f.config.ReplayNamespace = nil, ""
	storage := replay.SQLiteConfig{Path: filepath.Join(t.TempDir(), "replay.db"), Namespace: "gateway", Epoch: [32]byte{1}, Capacity: 150, CallerCapacity: 2, AdmittedRPS: 1}
	limits := ConnectionLimits{MaxConnections: 2, ConnectionsPerIP: 1}
	if _, err := OpenSQLiteRuntime(t.Context(), f.config, storage, limits); err == nil {
		t.Fatal("missing database was initialized")
	}
	must(t, replay.InitializeSQLite(t.Context(), storage))
	for _, invalid := range []ConnectionLimits{{}, {MaxConnections: 1}, {MaxConnections: 1, ConnectionsPerIP: 2}} {
		if _, err := OpenSQLiteRuntime(t.Context(), f.config, storage, invalid); !errors.Is(err, ErrConfig) {
			t.Fatal("invalid connection quotas accepted", err)
		}
	}
	runtime, err := OpenSQLiteRuntime(t.Context(), f.config, storage, limits)
	must(t, err)
	t.Cleanup(func() { _ = runtime.Shutdown(context.Background()) })
	if err := runtime.Serve(nil); !errors.Is(err, ErrConfig) {
		t.Fatal("nil listener accepted", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	serving := make(chan error, 1)
	go func() { serving <- runtime.Serve(listener) }()
	transport := &http.Transport{TLSClientConfig: f.clientTLS, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response := send(t, client, signedRequest(t, "https://"+listener.Addr().String(), publicURI, callerID, 0, f.call), 503)
	if response.Header.Get("Retry-After") != "1" || f.calls.Load() != 0 {
		t.Fatal("recovery barrier bypassed")
	}
	_ = response.Body.Close()
	// An authenticated idle connection consumes the per-IP slot. A second
	// TCP connection is closed without requiring any ClientHello bytes.
	idle, err := tls.Dial("tcp", listener.Addr().String(), f.clientTLS)
	must(t, err)
	t.Cleanup(func() { _ = idle.Close() })
	excess, err := net.Dial("tcp", listener.Addr().String())
	must(t, err)
	t.Cleanup(func() { _ = excess.Close() })
	must(t, excess.SetReadDeadline(time.Now().Add(time.Second)))
	var oneByte [1]byte
	if _, err := excess.Read(oneByte[:]); err == nil {
		t.Fatal("excess connection was not closed before TLS")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("excess connection retained awaiting TLS")
	}
	_ = idle.Close()
	must(t, runtime.Shutdown(t.Context()))
	if err := <-serving; !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}

type queuedListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func (l *queuedListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *queuedListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (*queuedListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9443} }

type peerConn struct {
	net.Conn
	address net.Addr
	closed  chan struct{}
	once    sync.Once
}

func (c *peerConn) RemoteAddr() net.Addr { return c.address }
func (c *peerConn) Close() error         { c.once.Do(func() { close(c.closed) }); return c.Conn.Close() }

func TestConnectionQuotasBeforeTLSAndReleaseOnClose(t *testing.T) {
	queue := &queuedListener{connections: make(chan net.Conn, 10), done: make(chan struct{})}
	t.Cleanup(func() { _ = queue.Close() })
	wrapped, err := LimitListener(queue, ConnectionLimits{MaxConnections: 2, ConnectionsPerIP: 1})
	must(t, err)
	limited := wrapped.(*quotaListener)
	connection := func(ip string) *peerConn {
		server, client := net.Pipe()
		t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
		return &peerConn{Conn: server, address: &net.TCPAddr{IP: net.ParseIP(ip), Port: 1234}, closed: make(chan struct{})}
	}
	first := connection("192.0.2.1")
	mapped := connection("::ffff:192.0.2.1")
	second := connection("192.0.2.2")
	queue.connections <- first
	one, err := limited.Accept()
	must(t, err)
	queue.connections <- mapped
	queue.connections <- second
	two, err := limited.Accept()
	must(t, err)
	select {
	case <-mapped.closed:
	default:
		t.Fatal("mapped address bypassed per-IP quota")
	}
	excess := connection("192.0.2.3")
	queue.connections <- excess
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := limited.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	select {
	case <-excess.closed:
	case <-time.After(time.Second):
		t.Fatal("global excess was not rejected")
	}
	must(t, one.Close())
	_ = one.Close()
	replacement := connection("192.0.2.1")
	queue.connections <- replacement
	var three net.Conn
	select {
	case three = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("quota not released")
	}
	must(t, two.Close())
	must(t, three.Close())
	limited.mu.Lock()
	defer limited.mu.Unlock()
	if limited.total != 0 || len(limited.peers) != 0 {
		t.Fatal("connection counters leaked")
	}
}

func TestLimitListenerRejectsInvalidLimitsWithoutTakingOwnership(t *testing.T) {
	for _, limits := range []ConnectionLimits{{}, {MaxConnections: 1}, {MaxConnections: 1, ConnectionsPerIP: 2}} {
		queue := &queuedListener{connections: make(chan net.Conn), done: make(chan struct{})}
		if _, err := LimitListener(queue, limits); err != ErrConfig {
			t.Fatal("accepted invalid limits", err)
		}
		select {
		case <-queue.done:
			t.Fatal("closed rejected listener")
		default:
		}
		_ = queue.Close()
	}
	if _, err := LimitListener(nil, ConnectionLimits{MaxConnections: 1, ConnectionsPerIP: 1}); err != ErrConfig {
		t.Fatal("accepted nil listener")
	}
}
