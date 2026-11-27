package servicecall

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/replay"
	"github.com/solodyagin/outgate/internal/registry"
)

const (
	callerID  = "sender"
	targetID  = "receiver"
	grantID   = "sender-grant"
	publicURI = "/api/%69tems?x=%2b&x="
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type transport struct {
	handle *registry.Session
	send   func(*http.Request) (*http.Response, error)
}

func (s transport) Handle() *registry.Session                         { return s.handle }
func (s transport) RoundTrip(r *http.Request) (*http.Response, error) { return s.send(r) }

type memoryReplay struct {
	mu          sync.Mutex
	calls       int
	entries     map[httpsig.ReplayKey]bool
	afterCommit func()
}

func (*memoryReplay) Ready(context.Context) error { return nil }
func (s *memoryReplay) Reserve(_ context.Context, entry httpsig.Reservation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.entries[entry.Key] {
		return httpsig.ErrReplay
	}
	s.entries[entry.Key] = true
	if s.afterCommit != nil {
		s.afterCommit()
	}
	return nil
}
func (s *memoryReplay) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type fixture struct {
	config          Config
	clientTLS       *tls.Config
	call, recipient delivery.Key
	replay          *memoryReplay
	calls           atomic.Int32
	selected        *registry.Session
}

func testFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		call:      delivery.Key{ID: "sender-key", Secret: bytes.Repeat([]byte{11}, 32)},
		recipient: delivery.Key{ID: "recipient-key", Secret: bytes.Repeat([]byte{12}, 32)},
		replay:    &memoryReplay{entries: make(map[httpsig.ReplayKey]bool)},
	}
	routes, err := registry.New(registry.Config{Services: map[string]registry.ServiceConfig{
		targetID: {AllowedPaths: []string{"/api"}, Rollout: registry.Rollout{Stable: "v1"}},
		"nested": {AllowedPaths: []string{"/api/items"}, Rollout: registry.Rollout{Stable: "v1"}},
	}})
	must(t, err)
	register := v1.Register{Type: "register", ProtocolVersion: 1, Capabilities: v1.BaselineCapabilities(), RequiredCapabilities: v1.BaselineCapabilities(), ServiceID: targetID,
		InstanceID: "target-1", Version: "v1", Paths: []string{"/api"}, PathMode: "preserve", MaxConcurrentRequests: 4}
	r, err := routes.RegisterAuthorized(register, registry.QUIC)
	must(t, err)
	_, err = routes.BindTransport(r.Session, register, registry.QUIC)
	must(t, err)
	must(t, routes.SetReady(r.Session, true))
	must(t, routes.ActivateAuthorized(targetID, "/api", routes.Revision()))
	f.selected = r.Session
	cert, roots, clientCert := testCertificates(t)
	f.clientTLS = &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS13}
	f.config = Config{
		AllowedAuthorities: []string{"gateway.test:9443"},
		Certificate:        cert, ClientRoots: roots, TrustDomain: "test.example", Routes: routes, Replay: f.replay, ReplayNamespace: "gateway",
		Authenticate: func(_ context.Context, peer Peer, grant, keyID string) (delivery.Key, error) {
			if peer.ServiceID != callerID || peer.InstanceID != "sender-1" || grant != grantID || keyID != f.call.ID ||
				peer.SPKI != sha256.Sum256(clientCert.Leaf.RawSubjectPublicKeyInfo) {
				return delivery.Key{}, delivery.ErrDelivery
			}
			return f.call, nil
		},
		Authorize: func(_ context.Context, call Call) (time.Time, error) {
			if call.Peer.ServiceID != callerID || call.Target != targetID || call.Method != "POST" || call.Path != "/api/items" || call.HasUser {
				return time.Time{}, ErrForbidden
			}
			return time.Now().Add(time.Minute), nil
		},
		Resolve: func(_ context.Context, route registry.Decision) (Recipient, error) {
			return Recipient{Key: f.recipient, Transport: transport{handle: f.selected, send: func(req *http.Request) (*http.Response, error) {
				f.calls.Add(1)
				if f.replay.count() == 0 {
					t.Error("dispatch preceded replay reservation")
				}
				if req.URL.RequestURI() != publicURI || req.Host != req.URL.Host || req.Header.Get("X-Forwarded-For") != "127.0.0.1" ||
					req.Header.Get("X-Forwarded-Proto") != "https" || req.Header.Get("X-Forwarded-Host") != req.Host {
					t.Error("changed public URL or trusted forwarding metadata", req.URL)
				}
				verifier, err := delivery.New(delivery.Config{Leg: httpsig.Gateway})
				if err != nil {
					return nil, err
				}
				var headers []v1.Header
				for name, values := range req.Header {
					for _, value := range values {
						headers = append(headers, v1.Header{strings.ToLower(name), value})
					}
				}
				verified, err := verifier.Verify(httpsig.Request{Method: req.Method, Scheme: req.URL.Scheme, Authority: req.Host,
					RawURI: req.URL.RequestURI(), Headers: headers}, f.recipient, delivery.Binding{Caller: callerID, Target: targetID,
					GrantID: grantID, Instance: "target-1", Version: "v1", Prefix: "/api"}, time.Now())
				if err != nil || verified.HopLimit() != 3 {
					t.Error("recipient signature verification failed", err)
					return nil, errors.New("verification failed")
				}
				defer req.Body.Close()
				body, err := io.ReadAll(req.Body)
				if err != nil || string(body) != "streamed" {
					t.Error("request body did not reach transport", err)
					return nil, errors.New("missing body")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("response")), ContentLength: 8}, nil
			}}}, nil
		},
	}
	return f
}

func testCertificates(t *testing.T) (tls.Certificate, *x509.CertPool, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	must(t, err)
	ca, err := x509.ParseCertificate(der)
	must(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	issue := func(serial int64, use x509.ExtKeyUsage, uri *url.URL) tls.Certificate {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{use}, KeyUsage: x509.KeyUsageDigitalSignature}
		if uri != nil {
			leaf.URIs = []*url.URL{uri}
		} else {
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(t, err)
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &private.PublicKey, key)
		must(t, err)
		parsed, err := x509.ParseCertificate(der)
		must(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private, Leaf: parsed}
	}
	uri := &url.URL{Scheme: "spiffe", Host: "test.example", Path: "/service/sender/instance/sender-1"}
	return issue(2, x509.ExtKeyUsageServerAuth, nil), pool, issue(3, x509.ExtKeyUsageClientAuth, uri)
}

func runServer(t *testing.T, configured *http.Server, cfg *tls.Config) (string, *http.Client) {
	t.Helper()
	server := httptest.NewUnstartedServer(configured.Handler)
	server.TLS = configured.TLSConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	return server.URL, &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func signedRequest(t *testing.T, address, uri, caller string, revision uint64, key delivery.Key) *http.Request {
	t.Helper()
	return signedRequestForAuthority(t, address, "gateway.test:9443", uri, caller, revision, key)
}

func signedRequestForAuthority(t *testing.T, address, authority, uri, caller string, revision uint64, key delivery.Key) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), "POST", address+uri, strings.NewReader("streamed"))
	must(t, err)
	req.Host = authority
	fields := []v1.Header{{"x-outgate-caller-service", caller}, {"x-outgate-target-service", targetID}, {"x-outgate-deployment-grant-id", grantID},
		{"x-outgate-hop-limit", "3"}, {"x-outgate-context-headers", "[]"}, {"x-forwarded-for", "spoofed"}}
	if revision != 0 {
		fields = append(fields, v1.Header{"x-outgate-expected-route-revision", strconv.FormatUint(revision, 10)})
	}
	profile, err := httpsig.New(httpsig.Config{Leg: httpsig.Call})
	must(t, err)
	signature, err := profile.Sign(httpsig.Request{Method: req.Method, Scheme: "https", Authority: req.Host, RawURI: req.URL.RequestURI(), Headers: fields},
		key.ID, key.Secret, time.Now())
	must(t, err)
	for _, field := range fields {
		req.Header.Set(field[0], field[1])
	}
	req.Header.Set("Signature", signature.Signature)
	req.Header.Set("Signature-Input", signature.SignatureInput)
	return req
}

func send(t *testing.T, client *http.Client, req *http.Request, status int) *http.Response {
	t.Helper()
	response, err := client.Do(req)
	must(t, err)
	if response.StatusCode != status {
		_ = response.Body.Close()
		t.Fatalf("status %d, want %d", response.StatusCode, status)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	return response
}

func TestSignedServiceListenerChecksAndResignsBeforeDispatch(t *testing.T) {
	f := testFixture(t)
	configured, err := NewServer(f.config)
	must(t, err)
	address, client := runServer(t, configured, f.clientTLS)
	_, revision, err := f.config.Routes.Discovery(targetID)
	must(t, err)
	if revision < 2 {
		t.Fatal("route revision too small for test")
	}

	send(t, client, signedRequest(t, address, publicURI, "another-caller", 0, f.call), 401)
	tampered := signedRequest(t, address, publicURI, callerID, 0, f.call)
	tampered.Header.Set("X-Outgate-Hop-Limit", "2")
	send(t, client, tampered, 401)
	send(t, client, signedRequest(t, address, "/outgate/discovery/services/receiver", callerID, 0, f.call), 404)
	send(t, client, signedRequest(t, address, "/api/forbidden", callerID, 0, f.call), 403)
	stale := send(t, client, signedRequest(t, address, publicURI, callerID, revision-1, f.call), 409)
	if stale.Header.Get("X-Outgate-Error-Code") != "route_revision_conflict" || f.replay.count() != 0 || f.calls.Load() != 0 {
		t.Fatal("policy or stale discovery request spent a nonce")
	}
	first := signedRequest(t, address, publicURI, callerID, revision, f.call)
	good := send(t, client, first, 200)
	data, err := io.ReadAll(good.Body)
	must(t, err)
	if string(data) != "response" {
		t.Fatal("invalid relayed response")
	}
	second := first.Clone(t.Context())
	second.Body, err = first.GetBody()
	must(t, err)
	send(t, client, second, 401)
	if f.calls.Load() != 1 || f.replay.count() != 2 {
		t.Fatal("replay dispatched or admission count wrong")
	}

	withoutCertificate := f.clientTLS.Clone()
	withoutCertificate.Certificates = nil
	transport := &http.Transport{TLSClientConfig: withoutCertificate}
	t.Cleanup(transport.CloseIdleConnections)
	req := signedRequest(t, address, publicURI, callerID, revision, f.call)
	if response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(req); err == nil {
		_ = response.Body.Close()
		t.Fatal("listener accepted a client without mTLS certificate")
	}
}

func TestRouteChangeDuringReplayCommitDoesNotReroute(t *testing.T) {
	f := testFixture(t)
	nested := v1.Register{Type: "register", ProtocolVersion: 1, Capabilities: v1.BaselineCapabilities(), RequiredCapabilities: v1.BaselineCapabilities(), ServiceID: "nested", InstanceID: "nested-1",
		Version: "v1", Paths: []string{"/api/items"}, PathMode: "preserve", MaxConcurrentRequests: 2}
	r, err := f.config.Routes.RegisterAuthorized(nested, registry.QUIC)
	must(t, err)
	must(t, f.config.Routes.SetReady(r.Session, true))
	activated := make(chan error, 1)
	f.replay.afterCommit = func() {
		activated <- f.config.Routes.ActivateAuthorized("nested", "/api/items", f.config.Routes.Revision())
	}
	configured, err := NewServer(f.config)
	must(t, err)
	address, client := runServer(t, configured, f.clientTLS)
	send(t, client, signedRequest(t, address, publicURI, callerID, 0, f.call), 409)
	must(t, <-activated)
	if f.calls.Load() != 0 || f.replay.count() != 1 {
		t.Fatal("selected request rerouted after commit")
	}
}

func TestSQLiteServiceListenerRemainsClosedDuringRecovery(t *testing.T) {
	f := testFixture(t)
	f.config.Replay, f.config.ReplayNamespace = nil, ""
	storage := replay.SQLiteConfig{Path: filepath.Join(t.TempDir(), "replay.db"), Namespace: "gateway",
		Epoch: [32]byte{1}, Capacity: 150, CallerCapacity: 2, AdmittedRPS: 1}
	must(t, replay.InitializeSQLite(t.Context(), storage))
	configured, store, err := OpenSQLiteServer(t.Context(), f.config, storage)
	must(t, err)
	t.Cleanup(func() { _ = store.Close() })
	address, client := runServer(t, configured, f.clientTLS)
	response := send(t, client, signedRequest(t, address, publicURI, callerID, 0, f.call), 503)
	if response.Header.Get("Retry-After") != "1" || f.calls.Load() != 0 {
		t.Fatal("recovery barrier allowed dispatch")
	}
}

func TestServiceListenerRequiresExactAuthorityBeforeAdmission(t *testing.T) {
	f := testFixture(t)
	for _, authorities := range [][]string{nil, {}, {""}, {"https://gateway.test:9443"}, {"*.test:9443"}, {"gateway.test:0"}, {"gateway.test:9443", "gateway.test:9443"}} {
		config := f.config
		config.AllowedAuthorities = authorities
		if _, err := NewServer(config); !errors.Is(err, ErrConfig) {
			t.Fatalf("accepted invalid allowlist %q: %v", authorities, err)
		}
	}
	var authenticated atomic.Int32
	original := f.config.Authenticate
	f.config.Authenticate = func(ctx context.Context, peer Peer, grant, key string) (delivery.Key, error) {
		authenticated.Add(1)
		return original(ctx, peer, grant, key)
	}
	configured, err := NewServer(f.config)
	must(t, err)
	// Construction must take its own snapshot rather than retain a mutable slice.
	f.config.AllowedAuthorities[0] = "foreign.test:9443"
	address, client := runServer(t, configured, f.clientTLS)
	for _, authority := range []string{"foreign.test:9443", "gateway.test", "gateway.test:443", "gateway.test:09443", "GATEWAY.test:9443"} {
		send(t, client, signedRequestForAuthority(t, address, authority, publicURI, callerID, 0, f.call), http.StatusMisdirectedRequest)
	}
	if authenticated.Load() != 0 || f.replay.count() != 0 || f.calls.Load() != 0 {
		t.Fatal("foreign authority reached security callbacks or dispatch")
	}
	send(t, client, signedRequest(t, address, publicURI, callerID, 0, f.call), http.StatusOK)
	if authenticated.Load() != 1 || f.calls.Load() != 1 {
		t.Fatal("allowed authority did not dispatch")
	}
}
