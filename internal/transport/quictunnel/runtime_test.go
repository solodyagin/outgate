package quictunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/replay"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/registry"
)

type runtimeFixture struct {
	config     SQLiteRuntimeConfig
	limits     RuntimeLimits
	client     *tls.Config
	reg        v1.Register
	credential string
}

func runtimeFixtureConfig(t *testing.T) *runtimeFixture {
	t.Helper()
	return runtimeFixtureServerTTL(t, time.Hour)
}

func runtimeFixtureServerTTL(t *testing.T, serverTTL time.Duration) *runtimeFixture {
	t.Helper()
	reg, _ := Fixtures(t, true)
	reg.ProtocolMinor = 1
	reg.Capabilities = append(reg.Capabilities, "credential_generation")
	reg.RequiredCapabilities = append(reg.RequiredCapabilities, "credential_generation")
	gen := v1.U64(7)
	reg.CredentialGeneration = &gen
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	must(t, err)
	ca, err = x509.ParseCertificate(caDER)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	cert := func(serial int64, client bool) tls.Certificate {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(t, err)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			leaf.URIs = []*url.URL{{Scheme: "spiffe", Host: "outgate.test", Path: "/service/" + reg.ServiceID + "/instance/" + reg.InstanceID}}
		} else {
			leaf.NotAfter = time.Now().Add(serverTTL)
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
		must(t, err)
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: leafKey}
	}
	server, client := cert(2, false), cert(3, true)
	control := controlstate.Config{Path: filepath.Join(t.TempDir(), "control.db"), Epoch: [32]byte{3}, Services: map[string][]string{reg.ServiceID: reg.Paths}}
	must(t, controlstate.Initialize(t.Context(), control))
	store, err := controlstate.Open(t.Context(), control)
	must(t, err)
	change := func(revision uint64) controlstate.Change {
		id, err := uuid.NewV7()
		must(t, err)
		return controlstate.Change{OperationID: id.String(), Actor: "operator", ExpectedRevision: revision, Reason: "QUIC runtime acceptance"}
	}
	clientLeaf, err := x509.ParseCertificate(client.Certificate[0])
	must(t, err)
	spki := sha256.Sum256(clientLeaf.RawSubjectPublicKeyInfo)
	issued, err := store.IssueGrant(t.Context(), change(1), controlstate.GrantBinding{ServiceID: reg.ServiceID, InstanceID: reg.InstanceID, Version: reg.Version, Paths: reg.Paths, Mounts: reg.Mounts, PathMode: reg.PathMode, RewriteMountHeaders: reg.RewriteMountHeaders, SPKI: hex.EncodeToString(spki[:]), ArtifactDigest: "sha256:" + strings.Repeat("a", 64), ExpiresAt: time.Now().Add(10 * time.Minute), CredentialGeneration: 7})
	must(t, err)
	registryConfig := registry.Config{Services: map[string]registry.ServiceConfig{reg.ServiceID: {AllowedPaths: reg.Paths, Rollout: registry.Rollout{Stable: reg.Version}}}}
	routes, err := registry.New(registryConfig)
	must(t, err)
	data, err := routes.MarshalSnapshot()
	must(t, err)
	_, err = store.CommitRegistry(t.Context(), change(2), registryConfig, data, nil)
	must(t, err)
	must(t, store.Close())
	replayConfig := replay.SQLiteConfig{Path: filepath.Join(t.TempDir(), "gateway-replay.db"), Namespace: "outgate:gateway", Epoch: [32]byte{4}, Capacity: 200, CallerCapacity: 100, AdmittedRPS: 1}
	must(t, replay.InitializeSQLite(t.Context(), replayConfig))
	policy := registrationPolicy(t)
	limits := RuntimeLimits{MaxConnections: 4, ConnectionsPerIP: 4, MaxHandshakes: 2, HandshakesPerIP: 2, BufferBytes: 128 << 20, BufferBytesPerService: 64 << 20, ConnectionOverheadBytes: 65536, StreamReceiveWindow: 32768, ConnectionReceiveWindow: 131072}
	return &runtimeFixture{config: SQLiteRuntimeConfig{Control: control, Registry: registryConfig, MinimumControlRevision: 3, Replay: replayConfig, Certificate: server, ClientRoots: roots, Admission: DurableAdmissionConfig{TrustDomain: "outgate.test", Limits: RegistrationLimits{PerServicePerMinute: 30, PerIPPerMinute: 10, MaxTrackedIPs: 10, MaxConcurrent: 2}, Policy: policy, Bound: BoundOptions{TickInterval: time.Millisecond}}}, limits: limits, client: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{client}, NextProtos: []string{v1.QUICALPN}, ServerName: "127.0.0.1"}, reg: reg, credential: issued.DeploymentGrant}
}

func startRuntime(t *testing.T, f *runtimeFixture) (*SQLiteRuntime, net.PacketConn, <-chan error) {
	t.Helper()
	runtime, err := OpenSQLiteRuntime(t.Context(), f.config, f.limits)
	must(t, err)
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	must(t, err)
	served := make(chan error, 1)
	go func() { served <- runtime.Serve(packet) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		must(t, runtime.Shutdown(ctx))
	})
	return runtime, packet, served
}

func runtimeBound(t *testing.T, r *SQLiteRuntime) *BoundSession {
	t.Helper()
	var bound *BoundSession
	eventually(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, current := range r.sessions {
			bound = current
			return true
		}
		return false
	})
	return bound
}

func runtimeRegister(t *testing.T, f *runtimeFixture, packet net.PacketConn) (*quic.Conn, *quiccontrol.Carrier, v1.RegisterAck) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, packet.LocalAddr().String(), f.client, &quic.Config{})
	must(t, err)
	t.Cleanup(func() { _ = conn.CloseWithError(quiccontrol.CodeNormal, "normal") })
	carrier, ack, err := quiccontrol.Open(ctx, conn, quiccontrol.Options{}, []byte(f.credential), f.reg)
	must(t, err)
	return conn, carrier, ack
}

func TestSQLiteRuntimePublishesExactHandlesAndOwnsShutdown(t *testing.T) {
	f := runtimeFixtureConfig(t)
	r, packet, served := startRuntime(t, f)
	firstConn, _, ack := runtimeRegister(t, f, packet)
	first := runtimeBound(t, r)
	got, err := r.Session(first.Handle())
	must(t, err)
	if got != first || ack.ReadyNotBefore <= time.Now().Unix() {
		t.Fatal("missing exact mapping/replay barrier")
	}
	eventually(t, func() bool { first.mu.Lock(); defer first.mu.Unlock(); return first.enabled })
	if err := r.Ready(t.Context()); err == nil {
		t.Fatal("warmup reported ready")
	}
	stats := r.Stats()
	if stats.Connections != 1 || stats.Handshakes != 0 || stats.Sessions != 1 || stats.ReservedBytes != r.charge {
		t.Fatal("wrong retained budget", stats)
	}
	durable, err := r.ControlStore().LoadRegistry(t.Context(), f.config.Registry, 5)
	must(t, err)
	if durable.Commit.RegistryRevision != 1 {
		t.Fatal("map preceded durable registration")
	}
	must(t, firstConn.CloseWithError(quiccontrol.CodeNormal, "normal"))
	eventually(t, func() bool { return r.Stats().Connections == 0 })
	if _, err := r.Session(first.Handle()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatal("stale handle resolved", err)
	}
	_, _, _ = runtimeRegister(t, f, packet)
	second := runtimeBound(t, r)
	if second.Handle() == first.Handle() {
		t.Fatal("reconnect reused handle")
	}
	if _, err := r.Session(first.Handle()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatal("old handle selected replacement", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	must(t, r.Shutdown(ctx))
	if err := await(t, served); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatal("unexpected Serve exit", err)
	}
	if stats := r.Stats(); stats.Connections != 0 || stats.Sessions != 0 || stats.ReservedBytes != 0 || !stats.Stopping {
		t.Fatal("shutdown leaked budget", stats)
	}
	if _, err := r.ControlStore().Revision(t.Context()); !errors.Is(err, controlstate.ErrUnavailable) {
		t.Fatal("control store remained open", err)
	}
	reopened, err := controlstate.Open(t.Context(), f.config.Control)
	must(t, err)
	must(t, reopened.Close())
}

func TestSQLiteRuntimeShutdownRetainsStoresAndQuotaThroughBlockedCleanup(t *testing.T) {
	f := runtimeFixtureConfig(t)
	r, packet, served := startRuntime(t, f)
	conn, _, _ := runtimeRegister(t, f, packet)
	bound := runtimeBound(t, r)
	entered := make(chan struct{})
	unblock := make(chan struct{})
	result := make(chan error, 1)
	var once sync.Once
	defer once.Do(func() { close(unblock) })
	reg := f.reg
	reg.InstanceID = "slow-publication"
	go func() {
		_, err := r.Routes().CommitRegistrationAuthorized(reg, registry.QUIC, func([]byte, uint64) error { close(entered); <-unblock; return controlstate.ErrUnavailable })
		result <- err
	}()
	await(t, entered)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := r.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shutdown ignored actual cleanup", err)
	}
	await(t, conn.Context().Done())
	if stats := r.Stats(); stats.Connections != 1 || stats.ReservedBytes != r.charge {
		t.Fatal("native close released cleanup budget", stats)
	}
	if _, err := r.Session(bound.Handle()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatal("shutdown still resolved transport", err)
	}
	if err := r.ControlStore().Close(); !errors.Is(err, controlstate.ErrInstanceInUse) {
		t.Fatal("lost durable owner lock", err)
	}
	once.Do(func() { close(unblock) })
	if err := await(t, result); !errors.Is(err, controlstate.ErrUnavailable) {
		t.Fatal("expected uncertain commit", err)
	}
	finish, cancelFinish := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancelFinish()
	must(t, r.Shutdown(finish))
	if err := await(t, served); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatal(err)
	}
}

func TestSQLiteRuntimeConnectionQuotaBeforeGrantWork(t *testing.T) {
	f := runtimeFixtureConfig(t)
	f.limits.MaxConnections = 1
	f.limits.ConnectionsPerIP = 1
	f.limits.MaxHandshakes = 1
	f.limits.HandshakesPerIP = 1
	r, packet, _ := startRuntime(t, f)
	_, _, _ = runtimeRegister(t, f, packet)
	_ = runtimeBound(t, r)
	before, err := r.ControlStore().Revision(t.Context())
	must(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, packet.LocalAddr().String(), f.client, &quic.Config{})
	if err == nil {
		_ = conn.CloseWithError(quiccontrol.CodeNormal, "normal")
		t.Fatal("exceeded connection quota")
	}
	after, err := r.ControlStore().Revision(t.Context())
	must(t, err)
	if after != before || r.Stats().Connections != 1 {
		t.Fatal("rejected connection reached SQL or evicted live owner")
	}
}

func TestSQLiteRuntimeHandshakeQuotaAndFailureRelease(t *testing.T) {
	f := runtimeFixtureConfig(t)
	f.limits.MaxHandshakes = 1
	f.limits.HandshakesPerIP = 1
	f.limits.HandshakeTimeout = 500 * time.Millisecond
	r, packet, _ := startRuntime(t, f)
	entered := make(chan struct{}, 1)
	unblock := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(unblock) })
	stalled := f.client.Clone()
	stalled.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		entered <- struct{}{}
		<-unblock
		return &f.client.Certificates[0], nil
	}
	dialed := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	go func() {
		conn, err := quic.DialAddr(ctx, packet.LocalAddr().String(), stalled, &quic.Config{})
		if conn != nil {
			select {
			case <-conn.Context().Done():
				err = context.Cause(conn.Context())
			case <-ctx.Done():
				err = ctx.Err()
			}
			_ = conn.CloseWithError(quiccontrol.CodeNormal, "normal")
		}
		dialed <- err
	}()
	await(t, entered)
	if r.Stats().Handshakes != 1 {
		t.Fatal("TLS work had no handshake reservation")
	}
	otherCtx, otherCancel := context.WithTimeout(t.Context(), time.Second)
	defer otherCancel()
	conn, err := quic.DialAddr(otherCtx, packet.LocalAddr().String(), f.client, &quic.Config{})
	if err == nil {
		_ = conn.CloseWithError(quiccontrol.CodeNormal, "normal")
		t.Fatal("second handshake exceeded quota")
	}
	eventually(t, func() bool { return r.Stats().Connections == 0 && r.Stats().Handshakes == 0 })
	once.Do(func() { close(unblock) })
	if err := await(t, dialed); err == nil {
		t.Fatal("stalled handshake unexpectedly completed")
	}
	revision, err := r.ControlStore().Revision(t.Context())
	must(t, err)
	if revision != 3 {
		t.Fatal("failed handshake reached storage mutation")
	}
}

func TestSQLiteRuntimeServiceBudgetNackBeforeGrantMutation(t *testing.T) {
	f := runtimeFixtureConfig(t)
	_, charge, err := runtimeTransport(f.limits, f.config.Admission.Policy)
	must(t, err)
	f.limits.BufferBytesPerService = charge
	r, packet, _ := startRuntime(t, f)
	_, _, _ = runtimeRegister(t, f, packet)
	_ = runtimeBound(t, r)
	revision, err := r.ControlStore().Revision(t.Context())
	must(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, packet.LocalAddr().String(), f.client, &quic.Config{})
	must(t, err)
	_, _, err = quiccontrol.Open(ctx, conn, quiccontrol.Options{}, []byte(f.credential), f.reg)
	var nack *quiccontrol.Rejection
	var application *quic.ApplicationError
	if errors.As(err, &nack) {
		if nack.Nack.Code != "quota_exceeded" || !nack.Nack.Retryable {
			t.Fatal("service quota misclassified", err)
		}
	} else if !errors.As(err, &application) || application.ErrorCode != 0x4f475407 {
		t.Fatal("service quota lost nack/close classification", err)
	}
	eventually(t, func() bool { return r.Stats().Connections == 1 })
	after, err := r.ControlStore().Revision(t.Context())
	must(t, err)
	if after != revision {
		t.Fatal("service quota committed generation fence")
	}
}

func TestSQLiteRuntimeRejectsUnauthenticatedTLSWithoutStorageMutation(t *testing.T) {
	for _, fault := range []string{"no_certificate", "untrusted_server", "wrong_alpn"} {
		t.Run(fault, func(t *testing.T) {
			f := runtimeFixtureConfig(t)
			r, packet, _ := startRuntime(t, f)
			client := f.client.Clone()
			switch fault {
			case "no_certificate":
				client.Certificates = nil
			case "untrusted_server":
				client.RootCAs = x509.NewCertPool()
			case "wrong_alpn":
				client.NextProtos = []string{"h3"}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, packet.LocalAddr().String(), client, &quic.Config{})
			if conn != nil {
				await(t, conn.Context().Done())
				_ = conn.CloseWithError(quiccontrol.CodeNormal, "normal")
			}
			if conn == nil && err == nil {
				t.Fatal("invalid TLS accepted")
			}
			eventually(t, func() bool { return r.Stats().Connections == 0 })
			revision, err := r.ControlStore().Revision(t.Context())
			must(t, err)
			if revision != 3 || r.Stats().Sessions != 0 {
				t.Fatal("unverified TLS reached durable admission")
			}
		})
	}
}

func TestSQLiteRuntimeServeFailureAndShutdownBeforeServe(t *testing.T) {
	for _, serve := range []bool{false, true} {
		t.Run(map[bool]string{false: "unstarted", true: "closed_socket"}[serve], func(t *testing.T) {
			f := runtimeFixtureConfig(t)
			r, err := OpenSQLiteRuntime(t.Context(), f.config, f.limits)
			must(t, err)
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			must(t, err)
			defer packet.Close()
			if serve {
				must(t, packet.Close())
				if err := r.Serve(packet); err == nil {
					t.Fatal("closed socket served successfully")
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			must(t, r.Shutdown(ctx))
			if err := r.Serve(packet); !errors.Is(err, ErrRuntimeClosed) {
				t.Fatal("restarted stopped runtime", err)
			}
			canceled, cancelAgain := context.WithCancel(t.Context())
			cancelAgain()
			must(t, r.Shutdown(canceled))
		})
	}
}

func TestSQLiteRuntimeKeepsOwnershipUntilAdditionalCheckerActuallyReturns(t *testing.T) {
	f := runtimeFixtureConfig(t)
	f.config.Admission.Renewal = SecurityRenewal{Interval: 20 * time.Millisecond, Timeout: time.Second}
	entered := make(chan struct{}, 1)
	unblock := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(unblock) })
	var calls atomic.Int32
	f.config.AdditionalSecurity = func(context.Context) (time.Time, error) {
		if calls.Add(1) > 2 {
			entered <- struct{}{}
			<-unblock
		}
		return time.Now().Add(4 * time.Second), nil
	}
	r, packet, _ := startRuntime(t, f)
	conn, _, _ := runtimeRegister(t, f, packet)
	_ = runtimeBound(t, r)
	await(t, entered)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := r.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("shutdown freed an outstanding checker", err)
	}
	await(t, conn.Context().Done())
	if r.Stats().Connections != 1 || r.Stats().ReservedBytes != r.charge || calls.Load() != 3 {
		t.Fatal("checker/connection slots were lost or duplicated")
	}
	if err := r.ControlStore().Close(); !errors.Is(err, controlstate.ErrInstanceInUse) {
		t.Fatal("store closed while checker held a lease", err)
	}
	once.Do(func() { close(unblock) })
	finish, done := context.WithTimeout(t.Context(), 3*time.Second)
	defer done()
	must(t, r.Shutdown(finish))
}

func TestSQLiteRuntimeDoesNotOutliveServerCertificate(t *testing.T) {
	f := runtimeFixtureServerTTL(t, 3*time.Second)
	r, packet, _ := startRuntime(t, f)
	_, _, ack := runtimeRegister(t, f, packet)
	bound := runtimeBound(t, r)
	if *ack.CredentialExpiresAt <= r.tls.Certificates[0].Leaf.NotAfter.Unix() {
		t.Fatal("test did not separate server and service credential bounds")
	}
	health, err := r.admission.security(t.Context())
	must(t, err)
	if health.ValidUntil.After(r.tls.Certificates[0].Leaf.NotAfter) {
		t.Fatal("health lease exceeded server identity lifetime")
	}
	await(t, bound.Done())
	if !errors.Is(bound.Err(), sessionstate.ErrSecurity) {
		t.Fatal("expired server certificate ignored", bound.Err())
	}
}
