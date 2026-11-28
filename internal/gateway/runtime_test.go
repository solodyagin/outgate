package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solodyagin/outgate/internal/registry"
	"github.com/solodyagin/outgate/internal/servicecall"
	"github.com/solodyagin/outgate/internal/transport/quictunnel"
)

// Only lifecycle tests use this owner. SQLite construction and the real replay
// barrier are covered separately; this fake never enters production wiring.
type testOwner struct {
	stop            chan struct{}
	once            sync.Once
	serving, closed atomic.Bool
	health          func(context.Context) error
	fail            error
	drain           func(time.Time) <-chan struct{}
	failure         chan error
}

func (o *testOwner) Serve(net.PacketConn) error {
	if o.fail != nil {
		return o.fail
	}
	o.serving.Store(true)
	select {
	case <-o.stop:
		return quictunnel.ErrRuntimeClosed
	case err := <-o.failure:
		return err
	}
}
func (o *testOwner) BeginDrain(deadline time.Time) <-chan struct{} {
	if o.drain != nil {
		return o.drain(deadline)
	}
	done := make(chan struct{})
	close(done)
	return done
}
func (o *testOwner) Stop()                          { o.once.Do(func() { close(o.stop) }) }
func (o *testOwner) Shutdown(context.Context) error { o.closed.Store(true); return nil }
func (o *testOwner) Ready(ctx context.Context) error {
	if !o.serving.Load() {
		return ErrClosed
	}
	if o.health != nil {
		return o.health(ctx)
	}
	return nil
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{{Scheme: "spiffe", Host: "outgate.test", Path: "/service/api/instance/one"}}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	check(t, err)
	parsed, err := x509.ParseCertificate(der)
	check(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}
func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}
func eventually(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition timed out")
}

func lifecycleRuntime(t *testing.T, handler http.Handler, owner *testOwner) (*Runtime, *http.Client, string, <-chan error) {
	t.Helper()
	certificate, roots := testCertificate(t)
	server := &http.Server{Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}}
	r := newRuntime(owner, server, servicecall.ConnectionLimits{MaxConnections: 4, ConnectionsPerIP: 4}, 1)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	check(t, err)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	check(t, err)
	done := make(chan error, 1)
	go func() { done <- r.Serve(tcp, udp) }()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		check(t, r.Shutdown(ctx))
		transport.CloseIdleConnections()
	})
	return r, client, "https://" + tcp.Addr().String(), done
}

func TestShutdownRetainsOwnerThroughUncooperativeHandler(t *testing.T) {
	entered, release, canceled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	owner := &testOwner{stop: make(chan struct{})}
	r, client, url, served := lifecycleRuntime(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		close(entered)
		<-req.Context().Done()
		close(canceled)
		<-release
	}), owner)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	eventually(t, func() bool { return r.Ready(t.Context()) == nil })
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
		}
	}()
	await(t, entered)
	resp, err := client.Get(url)
	check(t, err)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatal("missing request quota", resp.StatusCode)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if !errors.Is(r.Shutdown(ctx), context.DeadlineExceeded) {
		t.Fatal("shutdown released active owner")
	}
	await(t, canceled)
	if owner.closed.Load() {
		t.Fatal("stores closed under live handler")
	}
	if r.Ready(t.Context()) == nil {
		t.Fatal("stopping runtime ready")
	}
	denied := httptest.NewRecorder()
	r.server.Handler.ServeHTTP(denied, httptest.NewRequest("GET", "/", nil))
	if denied.Code != http.StatusServiceUnavailable {
		t.Fatal("admitted during shutdown")
	}
	close(release)
	check(t, r.Shutdown(t.Context()))
	if !owner.closed.Load() {
		t.Fatal("owner not closed after handler")
	}
	await(t, requestDone)
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestShutdownRetainsOwnerThroughHealthCallback(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	owner := &testOwner{stop: make(chan struct{}), health: func(context.Context) error { close(entered); <-release; return nil }}
	r, _, _, _ := lifecycleRuntime(t, http.NotFoundHandler(), owner)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	eventually(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.httpServing && owner.serving.Load() })
	readyDone := make(chan struct{})
	go func() { defer close(readyDone); _ = r.Ready(t.Context()) }()
	await(t, entered)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(r.Shutdown(ctx), context.Canceled) {
		t.Fatal("expected cancellation")
	}
	if owner.closed.Load() {
		t.Fatal("owner closed under health callback")
	}
	close(release)
	await(t, readyDone)
	check(t, r.Shutdown(t.Context()))
}

func TestListenerFailureStopsSibling(t *testing.T) {
	failure := errors.New("UDP listener failed")
	owner := &testOwner{stop: make(chan struct{}), fail: failure}
	r, _, _, served := lifecycleRuntime(t, http.NotFoundHandler(), owner)
	select {
	case err := <-served:
		if !errors.Is(err, failure) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sibling not stopped")
	}
	check(t, r.Shutdown(t.Context()))
	if r.Ready(t.Context()) == nil {
		t.Fatal("failed runtime ready")
	}
}

func TestShutdownBeforeServeRetainsRejectedSockets(t *testing.T) {
	for _, graceful := range []bool{false, true} {
		name := "immediate"
		if graceful {
			name = "graceful"
		}
		t.Run(name, func(t *testing.T) {
			owner := &testOwner{stop: make(chan struct{})}
			certificate, _ := testCertificate(t)
			r := newRuntime(owner, &http.Server{Handler: http.NotFoundHandler(), TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}}, servicecall.ConnectionLimits{MaxConnections: 1, ConnectionsPerIP: 1}, 1)
			if graceful {
				check(t, r.GracefulShutdown(t.Context()))
			} else {
				check(t, r.Shutdown(t.Context()))
			}
			tcp, err := net.Listen("tcp", "127.0.0.1:0")
			check(t, err)
			defer tcp.Close()
			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			check(t, err)
			defer udp.Close()
			if !errors.Is(r.Serve(tcp, udp), ErrClosed) {
				t.Fatal("accepted after shutdown")
			}
			probe, err := net.DialTimeout("tcp", tcp.Addr().String(), time.Second)
			check(t, err)
			probe.Close()
			if _, err := udp.WriteTo([]byte{1}, udp.LocalAddr()); err != nil {
				t.Fatal("closed rejected socket", err)
			}
		})
	}
}

func TestExactResolverDoesNotReselect(t *testing.T) {
	handle := new(registry.Session)
	sentinel := errors.New("stale handle")
	calls := 0
	resolve := exactResolver(func(got *registry.Session) (*quictunnel.BoundSession, error) {
		calls++
		if got != handle {
			t.Fatal("changed selected handle")
		}
		return nil, sentinel
	})
	if _, err := resolve(t.Context(), registry.Decision{Session: handle}); !errors.Is(err, sentinel) || calls != 1 {
		t.Fatal("retried stale session", err, calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolve(ctx, registry.Decision{Session: handle}); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("resolved canceled request", err, calls)
	}
}

func TestFreshRejectsUnboundedOrCanceledAssertions(t *testing.T) {
	for _, duration := range []time.Duration{-time.Second, 0, 6 * time.Second} {
		if _, err := fresh(t.Context(), func(context.Context) (time.Time, error) { return time.Now().Add(duration), nil }); err == nil {
			t.Fatal("accepted stale/unbounded assertion")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := fresh(ctx, func(context.Context) (time.Time, error) { return time.Now().Add(time.Second), nil }); err == nil {
		t.Fatal("accepted canceled assertion")
	}
}
