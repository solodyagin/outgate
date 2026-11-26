package quictunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solodyagin/outgate-sdk/delivery"
	"github.com/solodyagin/outgate-sdk/httpsig"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/registry"
	"github.com/solodyagin/outgate/internal/servicecall"
)

type testReplay struct{ committed atomic.Bool }

func (*testReplay) Ready(context.Context) error { return nil }
func (r *testReplay) Reserve(context.Context, httpsig.Reservation) error {
	if !r.committed.CompareAndSwap(false, true) {
		return httpsig.ErrReplay
	}
	return nil
}

func TestServiceListenerForwardsSignedDeliveryToBoundQUICSession(t *testing.T) {
	registered, _ := Fixtures(t, true)
	ingressKey := delivery.Key{ID: "sender-key", Secret: bytes.Repeat([]byte{1}, 32)}
	recipientKey := delivery.Key{ID: "recipient-key", Secret: bytes.Repeat([]byte{2}, 32)}
	const caller, grant = "sender", "sender-grant"
	prefix := registered.Paths[0]
	uri := prefix + "/%69tems?q=%2b"
	reserve := &testReplay{}
	verifier, err := delivery.New(delivery.Config{Leg: httpsig.Gateway})
	must(t, err)
	recipient, err := delivery.NewHandler(delivery.HandlerConfig{
		Verifier: verifier, ReplayStore: &testReplay{}, ReplayNamespace: "receiver", StripPrefix: true,
		Prepare: func(context.Context, *tls.ConnectionState, httpsig.Request) (delivery.Key, delivery.Binding, error) {
			return recipientKey, delivery.Binding{Caller: caller, GrantID: grant, Target: registered.ServiceID,
				Instance: registered.InstanceID, Version: registered.Version, Prefix: prefix}, nil
		},
		Authorize: func(context.Context, httpsig.Request, delivery.Verified) (time.Time, error) {
			return time.Now().Add(time.Minute), nil
		},
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !reserve.committed.Load() {
			t.Error("QUIC delivery before gateway replay commit")
		}
		signed, mount, ok := delivery.FromContext(r.Context())
		if !ok || signed.HopLimit() != 3 || mount.OriginalRequestURI != uri || r.RequestURI != "/%69tems?q=%2b" {
			t.Error("recipient did not receive original signed mount and escaped local URI")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "streamed" {
			t.Error("invalid QUIC request body", err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("relayed"))
	}))
	must(t, err)
	bound, _, routes, _ := driverPair(t, recipient, func(context.Context) error { return nil })
	// Ingress mTLS is tested with real TLS connections in servicecall. Here the
	// approved connection state isolates this test to the live QUIC dispatch.
	san := &url.URL{Scheme: "spiffe", Host: "test.example", Path: "/service/sender/instance/sender-1"}
	cert := &x509.Certificate{URIs: []*url.URL{san}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Minute)}
	server, err := servicecall.NewServer(servicecall.Config{
		Certificate: tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: struct{}{}},
		ClientRoots: x509.NewCertPool(), TrustDomain: san.Host, Routes: routes, Replay: reserve, ReplayNamespace: "gateway",
		Authenticate: func(context.Context, servicecall.Peer, string, string) (delivery.Key, error) { return ingressKey, nil },
		Authorize:    func(context.Context, servicecall.Call) (time.Time, error) { return time.Now().Add(time.Minute), nil },
		Resolve: func(context.Context, registry.Decision) (servicecall.Recipient, error) {
			return servicecall.Recipient{Transport: bound, Key: recipientKey}, nil
		},
		RewriteResponse: func(_ registry.Decision, _ *http.Response) error { return nil },
	})
	must(t, err)
	request := httptest.NewRequest(http.MethodPost, uri, strings.NewReader("streamed"))
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains: [][]*x509.Certificate{{cert}}}
	headers := []v1.Header{{"x-outgate-caller-service", caller}, {"x-outgate-target-service", registered.ServiceID},
		{"x-outgate-deployment-grant-id", grant}, {"x-outgate-hop-limit", "3"}, {"x-outgate-context-headers", "[]"}}
	profile, err := httpsig.New(httpsig.Config{Leg: httpsig.Call})
	must(t, err)
	sig, err := profile.Sign(httpsig.Request{Method: request.Method, Scheme: "https", Authority: request.Host, RawURI: uri, Headers: headers},
		ingressKey.ID, ingressKey.Secret, time.Now())
	must(t, err)
	for _, field := range headers {
		request.Header.Set(field[0], field[1])
	}
	request.Header.Set("Signature", sig.Signature)
	request.Header.Set("Signature-Input", sig.SignatureInput)
	response := httptest.NewRecorder()
	server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Body.String() != "relayed" {
		t.Fatalf("gateway response %d, %q", response.Code, response.Body.String())
	}
}
