package quictunnel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/registry"
)

type durableFixture struct {
	service, gateway *quic.Conn
	store            *controlstate.Store
	config           DurableAdmissionConfig
	registryConfig   registry.Config
	reg              v1.Register
	credential       string
	peer             controlstate.GrantPeer
}

func durableAdmissionFixture(t *testing.T) *durableFixture {
	t.Helper()
	reg, _ := Fixtures(t, true)
	reg.ProtocolMinor = 1
	reg.Capabilities = append(reg.Capabilities, "credential_generation")
	reg.RequiredCapabilities = append(reg.RequiredCapabilities, "credential_generation")
	generation := v1.U64(7)
	reg.CredentialGeneration = &generation
	identity := &url.URL{Scheme: "spiffe", Host: "outgate.test", Path: "/service/" + reg.ServiceID + "/instance/" + reg.InstanceID}
	service, gateway := pairWithIdentity(t, true, v1.QUICALPN, identity)
	cert := gateway.ConnectionState().TLS.PeerCertificates[0]
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	cfg := controlstate.Config{Path: filepath.Join(t.TempDir(), "control.db"), Epoch: [32]byte{1}, Services: map[string][]string{reg.ServiceID: reg.Paths}}
	must(t, controlstate.Initialize(t.Context(), cfg))
	store, err := controlstate.Open(t.Context(), cfg)
	must(t, err)
	t.Cleanup(func() { must(t, store.Close()) })
	change := func(rev uint64) controlstate.Change {
		op, err := uuid.NewV7()
		must(t, err)
		return controlstate.Change{OperationID: op.String(), Actor: "operator", ExpectedRevision: rev, Reason: "QUIC durable admission acceptance"}
	}
	issued, err := store.IssueGrant(t.Context(), change(1), controlstate.GrantBinding{ServiceID: reg.ServiceID, InstanceID: reg.InstanceID, Version: reg.Version, Paths: reg.Paths, Mounts: reg.Mounts, PathMode: reg.PathMode, RewriteMountHeaders: reg.RewriteMountHeaders, SPKI: hex.EncodeToString(spki[:]), ArtifactDigest: "sha256:" + strings.Repeat("a", 64), ExpiresAt: time.Now().Add(10 * time.Minute), CredentialGeneration: 7})
	must(t, err)
	rc := registry.Config{Services: map[string]registry.ServiceConfig{reg.ServiceID: {AllowedPaths: reg.Paths, Rollout: registry.Rollout{Stable: reg.Version}}}}
	bootstrap, err := registry.New(rc)
	must(t, err)
	data, err := bootstrap.MarshalSnapshot()
	must(t, err)
	_, err = store.CommitRegistry(t.Context(), change(2), rc, data, nil)
	must(t, err)
	owner, err := controlstate.OpenRegistrationOwner(t.Context(), store, rc, 3)
	must(t, err)
	config := DurableAdmissionConfig{Owner: owner, TrustDomain: "outgate.test", Limits: RegistrationLimits{PerIPPerMinute: 10, PerServicePerMinute: 30, MaxTrackedIPs: 100, MaxConcurrent: 2}, Policy: registrationPolicy(t), Bound: BoundOptions{TickInterval: time.Millisecond}, Security: func(context.Context) (AdmissionSecurity, error) {
		return AdmissionSecurity{ValidUntil: time.Now().Add(4 * time.Second)}, nil
	}}
	return &durableFixture{service: service, gateway: gateway, store: store, config: config, registryConfig: rc, reg: reg, credential: issued.DeploymentGrant, peer: controlstate.GrantPeer{ServiceID: reg.ServiceID, InstanceID: reg.InstanceID, SPKI: hex.EncodeToString(spki[:]), CertificateSerial: cert.SerialNumber.Text(16)}}
}

func (f *durableFixture) open(t *testing.T, a *DurableAdmission) (*BoundSession, *quiccontrol.Carrier, v1.RegisterAck, error, error) {
	t.Helper()
	type accepted struct {
		s   *BoundSession
		err error
	}
	result := make(chan accepted, 1)
	go func() { s, err := a.Accept(t.Context(), f.gateway); result <- accepted{s, err} }()
	carrier, ack, err := quiccontrol.Open(t.Context(), f.service, quiccontrol.Options{}, []byte(f.credential), f.reg)
	got := await(t, result)
	if got.s != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			must(t, got.s.Close(ctx))
		})
	}
	return got.s, carrier, ack, err, got.err
}

func TestDurableAdmissionRealQUICAckAndRecoveryBarrier(t *testing.T) {
	f := durableAdmissionFixture(t)
	barrier := time.Now().Add(120 * time.Second)
	var checks atomic.Int32
	f.config.Security = func(ctx context.Context) (AdmissionSecurity, error) {
		checks.Add(1)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			t.Error("unbounded security check")
		}
		return AdmissionSecurity{ValidUntil: time.Now().Add(4 * time.Second), ReadyNotBefore: barrier}, nil
	}
	f.reg.MaxConcurrentRequests = 1
	a, err := NewDurableAdmission(f.config)
	must(t, err)
	bound, carrier, ack, openErr, acceptErr := f.open(t, a)
	must(t, openErr)
	must(t, acceptErr)
	if checks.Load() != 2 || ack.Limits.MaxInflight != 1 || ack.ProtocolMinor != 1 || ack.CredentialGeneration == nil || *ack.CredentialGeneration != 7 || ack.CredentialExpiresAt == nil || ack.ReadyNotBefore != barrier.Unix()+1 {
		t.Fatal("ack lost verified/negotiated values", ack)
	}
	for _, path := range ack.Paths {
		if path.State != "pending" {
			t.Fatal("registration activated a path")
		}
	}
	must(t, bound.EnableDispatch())
	must(t, carrier.Send(t.Context(), v1.InstanceStatus{Type: "instance_status", Sequence: 1, Ready: true, Code: "ready", ObservedAt: 0}))
	eventually(t, func() bool { return bound.Snapshot().Sequence == 1 })
	if bound.Snapshot().Phase == sessionstate.Ready {
		t.Fatal("replay barrier bypassed")
	}
	if err := a.config.Owner.Routes().CanDispatch(bound.Handle()); err == nil {
		t.Fatal("barrier admitted dispatch")
	}
	durable, err := f.store.LoadRegistry(t.Context(), f.registryConfig, 5)
	must(t, err)
	if durable.Commit.RegistryRevision != 1 {
		t.Fatal("ack preceded durable snapshot")
	}
	if _, err := f.store.AcquireRegistration(t.Context(), f.credential, f.peer, f.reg); !errors.Is(err, controlstate.ErrInstanceInUse) {
		t.Fatal("transport lost lease", err)
	}
}

func TestDurableAdmissionFailuresCleanUpAndKeepOwnership(t *testing.T) {
	for _, fault := range []string{"health_before", "health_after", "credential", "unsupported", "stale_health", "zero_health", "long_health", "invalid_barrier", "ack_write"} {
		t.Run(fault, func(t *testing.T) {
			f := durableAdmissionFixture(t)
			var checks atomic.Int32
			f.config.Security = func(context.Context) (AdmissionSecurity, error) {
				n := checks.Add(1)
				if fault == "health_before" || fault == "health_after" && n == 2 {
					return AdmissionSecurity{}, controlstate.ErrUnavailable
				}
				state := AdmissionSecurity{ValidUntil: time.Now().Add(4 * time.Second)}
				switch fault {
				case "stale_health":
					state.ValidUntil = time.Now().Add(-time.Second)
				case "zero_health":
					state.ValidUntil = time.Time{}
				case "long_health":
					state.ValidUntil = time.Now().Add(time.Minute)
				case "invalid_barrier":
					state.ReadyNotBefore = time.Unix(-1, 0)
				case "ack_write":
					if n == 2 {
						_ = f.service.CloseWithError(quiccontrol.CodeNormal, "normal")
						await(t, f.gateway.Context().Done())
					}
				}
				return state, nil
			}
			if fault == "credential" {
				f.credential = "invalid"
			}
			if fault == "unsupported" {
				f.reg.Capabilities = append(f.reg.Capabilities, "unsupported_feature")
				f.reg.RequiredCapabilities = append(f.reg.RequiredCapabilities, "unsupported_feature")
			}
			a, err := NewDurableAdmission(f.config)
			must(t, err)
			bound, carrier, _, openErr, acceptErr := f.open(t, a)
			if openErr == nil || acceptErr == nil || bound != nil {
				if carrier != nil {
					_ = carrier.Close()
				}
				t.Fatal("invalid admission accepted", fault)
			}
			wantRevision := uint64(3)
			wantRegistry := uint64(0)
			if fault == "health_after" || fault == "ack_write" {
				wantRevision = 5
				wantRegistry = 1
			}
			revision, err := f.store.Revision(t.Context())
			must(t, err)
			durable, err := f.store.LoadRegistry(t.Context(), f.registryConfig, 3)
			must(t, err)
			if revision != wantRevision || durable.Commit.RegistryRevision != wantRegistry {
				t.Fatal("incorrect failure persistence", revision, durable.Commit)
			}
			if f.gateway.Context().Err() == nil {
				t.Fatal("returned before native close")
			}
			must(t, f.store.Close()) // No failed binding/session may retain admission ownership.
		})
	}
}

func TestDurableAdmissionGateBeforeCredentialWork(t *testing.T) {
	f := durableAdmissionFixture(t)
	f.config.Limits.PerIPPerMinute = 1
	var checks atomic.Int32
	f.config.Security = func(context.Context) (AdmissionSecurity, error) {
		checks.Add(1)
		return AdmissionSecurity{ValidUntil: time.Now().Add(4 * time.Second)}, nil
	}
	a, err := NewDurableAdmission(f.config)
	must(t, err)
	ip := netip.MustParseAddr("192.0.2.1")
	state := f.gateway.ConnectionState().TLS
	_, err = a.admit(t.Context(), state, ip, []byte("invalid"), f.reg)
	if err == nil {
		t.Fatal("invalid credential accepted")
	}
	revision, err := f.store.Revision(t.Context())
	must(t, err)
	_, err = a.admit(t.Context(), state, ip, []byte(f.credential), f.reg)
	var nack *quiccontrol.Rejection
	if !errors.As(err, &nack) || nack.Nack.Code != "quota_exceeded" || !nack.Nack.Retryable {
		t.Fatal("rate limit did not use existing wire code", err)
	}
	after, err := f.store.Revision(t.Context())
	must(t, err)
	if after != revision || checks.Load() != 1 || a.gate.active != 0 {
		t.Fatal("rate-limited request reached storage/security work")
	}
}

func TestDurableAdmissionRejectsInvalidConfiguration(t *testing.T) {
	f := durableAdmissionFixture(t)
	for _, mutate := range []func(*DurableAdmissionConfig){
		func(c *DurableAdmissionConfig) { c.Owner = nil }, func(c *DurableAdmissionConfig) { c.Security = nil }, func(c *DurableAdmissionConfig) { c.TrustDomain = "invalid:443" }, func(c *DurableAdmissionConfig) { c.Bound.Transport.Development = true }, func(c *DurableAdmissionConfig) { c.Bound.MaxCommands = 2049 }, func(c *DurableAdmissionConfig) { c.Policy.Limits.MaxControlBytes = 1 }, func(c *DurableAdmissionConfig) { c.Limits.MaxConcurrent = 0 }, func(c *DurableAdmissionConfig) { c.Policy.Timeouts.RegisterMS = 10001 }, func(c *DurableAdmissionConfig) { c.Bound.Transport.RegisterTimeout = time.Second },
	} {
		config := f.config
		mutate(&config)
		if _, err := NewDurableAdmission(config); !errors.Is(err, controlstate.ErrConfig) {
			t.Fatal("invalid configuration accepted", err)
		}
	}
	a, err := NewDurableAdmission(f.config)
	must(t, err)
	original := a.config.Policy.Capabilities[0]
	f.config.Policy.Capabilities[0] = "changed"
	if a.config.Policy.Capabilities[0] != original {
		t.Fatal("mutable configuration escaped")
	}
	if _, err := a.Accept(t.Context(), nil); !errors.Is(err, controlstate.ErrConfig) {
		t.Fatal("nil connection accepted")
	}
}

func TestDurableAdmissionRejectsCanceledOrUnverifiedPeer(t *testing.T) {
	f := durableAdmissionFixture(t)
	a, err := NewDurableAdmission(f.config)
	must(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = a.admit(ctx, f.gateway.ConnectionState().TLS, netip.MustParseAddr("192.0.2.1"), []byte(f.credential), f.reg)
	if !errors.Is(err, context.Canceled) || len(a.gate.ips) != 0 {
		t.Fatal("canceled admission consumed budget", err)
	}
	_, err = a.admit(t.Context(), tls.ConnectionState{}, netip.MustParseAddr("192.0.2.1"), []byte(f.credential), f.reg)
	var nack *quiccontrol.Rejection
	if !errors.As(err, &nack) || nack.Nack.Code != "auth_failed" {
		t.Fatal("unverified principal admitted", err)
	}
	revision, err := f.store.Revision(t.Context())
	must(t, err)
	if revision != 3 || a.gate.active != 0 {
		t.Fatal("unverified peer reached durable state")
	}
}

func TestDurableAdmissionPublicationGateAndBoundedHealth(t *testing.T) {
	f := durableAdmissionFixture(t)
	var checks atomic.Int32
	f.config.Security = func(context.Context) (AdmissionSecurity, error) {
		checks.Add(1)
		return AdmissionSecurity{ValidUntil: time.Now().Add(4 * time.Second)}, nil
	}
	a, err := NewDurableAdmission(f.config)
	must(t, err)
	_, err = f.config.Owner.Routes().CommitRegistrationAuthorized(f.reg, registry.QUIC, func([]byte, uint64) error { return controlstate.ErrUnavailable })
	if !errors.Is(err, controlstate.ErrUnavailable) {
		t.Fatal("expected publication failure")
	}
	_, err = a.admit(t.Context(), f.gateway.ConnectionState().TLS, netip.MustParseAddr("192.0.2.1"), []byte(f.credential), f.reg)
	if !errors.Is(err, registry.ErrPublicationUnavailable) || checks.Load() != 0 {
		t.Fatal("closed publication reached security/credential work", err)
	}
	revision, err := f.store.Revision(t.Context())
	must(t, err)
	if revision != 3 {
		t.Fatal("closed publication advanced generation")
	}
	must(t, f.config.Owner.Resync(t.Context()))
	must(t, f.config.Owner.Routes().CheckPublication())
	a.config.Security = func(ctx context.Context) (AdmissionSecurity, error) {
		<-ctx.Done()
		return AdmissionSecurity{ValidUntil: time.Now().Add(time.Second)}, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	if _, err := a.security(ctx); !errors.Is(err, controlstate.ErrUnavailable) {
		t.Fatal("late health result accepted", err)
	}
}

func TestDurableAdmissionServiceQuotaUsesTLSPrincipal(t *testing.T) {
	f := durableAdmissionFixture(t)
	f.config.Limits.PerServicePerMinute = 1
	a, err := NewDurableAdmission(f.config)
	must(t, err)
	forged := f.reg
	forged.ServiceID = "forged-service"
	_, err = a.admit(t.Context(), f.gateway.ConnectionState().TLS, netip.MustParseAddr("192.0.2.1"), []byte("invalid"), forged)
	if err == nil {
		t.Fatal("forged registration accepted")
	}
	_, err = a.admit(t.Context(), f.gateway.ConnectionState().TLS, netip.MustParseAddr("192.0.2.2"), []byte(f.credential), f.reg)
	var nack *quiccontrol.Rejection
	if !errors.As(err, &nack) || nack.Nack.Code != "quota_exceeded" || len(a.gate.services) != 1 {
		t.Fatal("claimed principal bypassed service budget", err)
	}
	revision, err := f.store.Revision(t.Context())
	must(t, err)
	if revision != 3 {
		t.Fatal("rate limited registration committed generation")
	}
}
