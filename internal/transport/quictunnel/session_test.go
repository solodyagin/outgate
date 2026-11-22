package quictunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quichttp"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func Fixtures(t *testing.T, production bool) (v1.Register, v1.RegisterAck) {
	t.Helper()
	b, err := os.ReadFile("../../../tests/fixtures/protocol/v1/control-messages.json")
	must(t, err)
	var corpus struct{ Positive []json.RawMessage }
	must(t, json.Unmarshal(b, &corpus))
	var reg v1.Register
	var ack v1.RegisterAck
	for _, b := range corpus.Positive {
		var tag struct{ Type string }
		must(t, json.Unmarshal(b, &tag))
		switch tag.Type {
		case "register":
			reg, err = v1.DecodeRegister(b)
			must(t, err)
		case "register_ack":
			ack, err = v1.DecodeRegisterAck(b)
			must(t, err)
		}
	}
	if production {
		expiry := time.Now().Add(time.Hour).Unix()
		ack.CredentialExpiresAt = &expiry
	}
	must(t, ack.ValidateForRegister(reg, v1.RegisterAckValidationOptions{Development: !production}))
	return reg, ack
}

func Pair(t *testing.T, mutual bool, alpn string) (*quic.Conn, *quic.Conn) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(t, err)
	cert, err := x509.ParseCertificate(der)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{alpn}}
	clientTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{alpn}}
	if mutual {
		serverTLS.ClientAuth = tls.RequireAndVerifyClientCert
		serverTLS.ClientCAs = roots
		clientTLS.Certificates = []tls.Certificate{certificate}
	}
	// Small native stream windows exercise write backpressure without large data.
	config := &quic.Config{MaxIdleTimeout: 45 * time.Second, KeepAlivePeriod: 15 * time.Second,
		InitialStreamReceiveWindow: 32 * 1024, MaxStreamReceiveWindow: 32 * 1024}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, config)
	must(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	service, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, config)
	must(t, err)
	t.Cleanup(func() { _ = service.CloseWithError(quic.ApplicationErrorCode(0x4f475400), "normal") })
	gateway, err := listener.Accept(ctx)
	must(t, err)
	t.Cleanup(func() { _ = gateway.CloseWithError(quic.ApplicationErrorCode(0x4f475400), "normal") })
	return service, gateway
}

func await[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("operation stalled")
		var zero T
		return zero
	}
}

func TestPublishedSDKRegistrationHTTPAndControl(t *testing.T) {
	serviceConn, gatewayConn := Pair(t, true, v1.QUICALPN)
	reg, ack := Fixtures(t, true)
	type accepted struct {
		session *Session
		err     error
	}
	result := make(chan accepted, 1)
	go func() {
		s, err := Accept(t.Context(), gatewayConn, quiccontrol.Options{}, func(_ context.Context, peer tls.ConnectionState, credential []byte, register v1.Register) (v1.RegisterAck, error) {
			if len(peer.VerifiedChains) == 0 || string(credential) != "test-only-grant" || register.InstanceID != reg.InstanceID {
				return v1.RegisterAck{}, errors.New("denied")
			}
			return ack, nil
		})
		result <- accepted{s, err}
	}()
	control, _, err := quiccontrol.Open(t.Context(), serviceConn, quiccontrol.Options{}, []byte("test-only-grant"), reg)
	must(t, err)
	acceptedSession := await(t, result)
	must(t, acceptedSession.err)
	session := acceptedSession.session
	service, err := quichttp.NewService(control, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Tunnel-Request-Id") != "" || r.Host != "public.example.test" || r.URL.RawQuery != "q=%2f&q=two" {
			panic(http.ErrAbortHandler)
		}
		_, _ = io.Copy(w, r.Body)
	}))
	must(t, err)
	served := make(chan error, 1)
	go func() { served <- service.Serve() }()
	t.Cleanup(func() { _ = session.Close(); _ = service.Close(); _ = await(t, served) })
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://public.example.test/api/echo?q=%2f&q=two", strings.NewReader("body through published SDK"))
	must(t, err)
	req.Header.Set("X-Tunnel-Request-Id", "spoofed-external-id")
	response, err := session.RoundTrip(req)
	must(t, err)
	body, err := io.ReadAll(response.Body)
	must(t, err)
	must(t, response.Body.Close())
	if string(body) != "body through published SDK" {
		t.Fatal("body changed")
	}
	must(t, control.Send(t.Context(), v1.InstanceStatus{Type: "instance_status", Sequence: 1, Ready: true, Code: "ready", ObservedAt: time.Now().Unix()}))
	message, err := session.Receive(t.Context())
	must(t, err)
	if message.(v1.InstanceStatus).Sequence != 1 {
		t.Fatal("status changed")
	}
	must(t, session.Send(t.Context(), v1.Drain{Type: "drain", CommandID: 1, DeadlineMS: 1000, Code: "shutdown"}))
	message, err = control.Receive(t.Context())
	must(t, err)
	if message.(v1.Drain).CommandID != 1 {
		t.Fatal("drain changed")
	}
	must(t, control.Close())
	await(t, session.Done())
	if session.Err() == nil {
		t.Fatal("lost carrier still selectable")
	}
}

func TestAuthorizationRefusalDoesNotReturnSession(t *testing.T) {
	serviceConn, gatewayConn := Pair(t, true, v1.QUICALPN)
	reg, _ := Fixtures(t, true)
	result := make(chan error, 1)
	go func() {
		session, err := Accept(t.Context(), gatewayConn, quiccontrol.Options{}, func(context.Context, tls.ConnectionState, []byte, v1.Register) (v1.RegisterAck, error) {
			return v1.RegisterAck{}, &quiccontrol.Rejection{Nack: v1.RegisterNack{Type: "register_nack", Code: "auth_failed", Detail: "denied", Retryable: false}}
		})
		if session != nil {
			result <- errors.New("partial session returned")
			return
		}
		result <- err
	}()
	if _, _, err := quiccontrol.Open(t.Context(), serviceConn, quiccontrol.Options{}, []byte("invalid-test-grant"), reg); err == nil {
		t.Fatal("refused registration accepted")
	}
	var refused *quiccontrol.Rejection
	if err := await(t, result); !errors.As(err, &refused) || refused.Nack.Code != "auth_failed" {
		t.Fatal("refusal lost", err)
	}
}
