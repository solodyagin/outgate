package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/solodyagin/outgate-sdk/delivery"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/replay"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/registry"
	"github.com/solodyagin/outgate/internal/servicecall"
	"github.com/solodyagin/outgate/internal/transport/quictunnel"
)

func sqliteConfig(t *testing.T) Config {
	t.Helper()
	certificate, roots := testCertificate(t)
	control := controlstate.Config{Path: filepath.Join(t.TempDir(), "control.db"), Epoch: [32]byte{1}, Services: map[string][]string{"api": {"/api"}}}
	check(t, controlstate.Initialize(t.Context(), control))
	store, err := controlstate.Open(t.Context(), control)
	check(t, err)
	routes := registry.Config{Services: map[string]registry.ServiceConfig{"api": {AllowedPaths: []string{"/api"}, Rollout: registry.Rollout{Stable: "1.0.0"}}}}
	registryStore, err := registry.New(routes)
	check(t, err)
	data, err := registryStore.MarshalSnapshot()
	check(t, err)
	id, err := uuid.NewV7()
	check(t, err)
	_, err = store.CommitRegistry(t.Context(), controlstate.Change{OperationID: id.String(), Actor: "operator", ExpectedRevision: 1, Reason: "shared runtime test"}, routes, data, nil)
	check(t, err)
	check(t, store.Close())
	storage := replay.SQLiteConfig{Path: filepath.Join(t.TempDir(), "replay.db"), Namespace: "outgate:gateway", Epoch: [32]byte{2}, Capacity: 200, CallerCapacity: 100, AdmittedRPS: 1}
	check(t, replay.InitializeSQLite(t.Context(), storage))
	corpusData, err := os.ReadFile("../../tests/fixtures/protocol/v1/control-messages.json")
	check(t, err)
	var corpus struct{ Positive []json.RawMessage }
	check(t, json.Unmarshal(corpusData, &corpus))
	var ack v1.RegisterAck
	for _, message := range corpus.Positive {
		var tag struct{ Type string }
		check(t, json.Unmarshal(message, &tag))
		if tag.Type == "register_ack" {
			ack, err = v1.DecodeRegisterAck(message)
			check(t, err)
		}
	}
	policy := quictunnel.RegistrationPolicy{ProtocolMinor: 1, Capabilities: append(ack.Capabilities, "credential_generation"), RequiredCapabilities: ack.RequiredCapabilities, Limits: ack.Limits, Timeouts: ack.Timeouts, Readiness: ack.Readiness}
	return Config{
		Tunnel:       quictunnel.SQLiteRuntimeConfig{Control: control, Registry: routes, MinimumControlRevision: 2, Replay: storage, Certificate: certificate, ClientRoots: roots, Admission: quictunnel.DurableAdmissionConfig{TrustDomain: "outgate.test", Limits: quictunnel.RegistrationLimits{PerServicePerMinute: 30, PerIPPerMinute: 10, MaxTrackedIPs: 10, MaxConcurrent: 2}, Policy: policy}},
		TunnelLimits: quictunnel.RuntimeLimits{MaxConnections: 4, ConnectionsPerIP: 4, MaxHandshakes: 2, HandshakesPerIP: 2, BufferBytes: 128 << 20, BufferBytesPerService: 64 << 20, ConnectionOverheadBytes: 65536, StreamReceiveWindow: 32768, ConnectionReceiveWindow: 131072},
		Service:      servicecall.Config{AllowedAuthorities: []string{"gateway.test:443"}},
		State: servicecall.StateConfig{Callers: map[string]servicecall.CallerLimit{"api": {PerSecond: 1, Burst: 1}}, Keys: func(context.Context, string, string, string) (servicecall.AcceptedKey, error) {
			return servicecall.AcceptedKey{Key: delivery.Key{}, NotAfter: time.Now().Add(time.Minute)}, nil
		}},
		Connections: servicecall.ConnectionLimits{MaxConnections: 4, ConnectionsPerIP: 4}, MaxRequests: 4,
		KeyHealth: func(context.Context) (time.Time, error) { return time.Now().Add(time.Second), nil },
	}
}

func TestSQLiteCompositionPreservesBarrierAndRetainsBothStores(t *testing.T) {
	config := sqliteConfig(t)
	var block atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	config.KeyHealth = func(context.Context) (time.Time, error) {
		if block.Load() {
			once.Do(func() { close(entered) })
			<-release
		}
		return time.Now().Add(time.Second), nil
	}
	r, err := OpenSQLiteRuntime(t.Context(), config)
	check(t, err)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		check(t, r.Shutdown(ctx))
	})
	owner := r.tunnel.(*quictunnel.SQLiteRuntime)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	check(t, err)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	check(t, err)
	served := make(chan error, 1)
	go func() { served <- r.Serve(tcp, udp) }()
	eventually(t, func() bool {
		r.mu.Lock()
		live := r.httpServing
		r.mu.Unlock()
		return live && owner.Ready(t.Context()) != quictunnel.ErrRuntimeClosed
	})
	if r.Ready(t.Context()) == nil {
		t.Fatal("real replay warmup bypassed")
	}
	if _, err = owner.ReplayStore().Health(t.Context()); err != nil {
		t.Fatal("warming store unhealthy", err)
	}
	// An ordinary request cannot reach signature/authz/dispatch during warmup.
	recorder := httptest.NewRecorder()
	r.server.Handler.ServeHTTP(recorder, httptest.NewRequest("GET", "https://gateway.test:443/api", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatal("warmup ingress admitted", recorder.Code)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: config.Tunnel.ClientRoots, Certificates: []tls.Certificate{config.Tunnel.Certificate}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("https://" + tcp.Addr().String() + "/api")
	check(t, err)
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatal("real mTLS warmup ingress admitted", response.StatusCode)
	}

	block.Store(true)
	done := make(chan struct{})
	go func() { defer close(done); _ = r.Ready(t.Context()) }()
	await(t, entered)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if !errors.Is(r.Shutdown(ctx), context.DeadlineExceeded) {
		t.Fatal("released blocked health owner")
	}
	if _, err = owner.ControlStore().Revision(t.Context()); err != nil {
		t.Fatal("closed shared control store", err)
	}
	if _, err = owner.ReplayStore().Health(t.Context()); err != nil {
		t.Fatal("closed shared replay store", err)
	}
	if other, err := controlstate.Open(t.Context(), config.Tunnel.Control); err == nil {
		other.Close()
		t.Fatal("lost control store ownership")
	}
	close(release)
	await(t, done)
	check(t, r.Shutdown(t.Context()))
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("listeners not stopped")
	}
	reopened, err := controlstate.Open(t.Context(), config.Tunnel.Control)
	check(t, err)
	check(t, reopened.Close())
	replayStore, err := replay.OpenSQLite(t.Context(), config.Tunnel.Replay)
	check(t, err)
	check(t, replayStore.Close())
}

func TestSQLiteCompositionRejectsOverridesAndCleansFailedConstruction(t *testing.T) {
	config := sqliteConfig(t)
	broken := config
	broken.State.Keys = nil
	if r, err := OpenSQLiteRuntime(t.Context(), broken); err == nil {
		r.Shutdown(t.Context())
		t.Fatal("missing key source accepted")
	}
	r, err := OpenSQLiteRuntime(t.Context(), config)
	check(t, err)
	check(t, r.Shutdown(t.Context()))
	cases := []func(*Config){
		func(c *Config) {
			c.Service.Resolve = func(context.Context, registry.Decision) (servicecall.Recipient, error) {
				return servicecall.Recipient{}, nil
			}
		},
		func(c *Config) { c.Service.ReplayNamespace = "override" },
		func(c *Config) { c.Service.Certificate = c.Tunnel.Certificate },
		func(c *Config) { c.Service.TrustDomain = "override.test" },
		func(c *Config) { c.KeyHealth = nil },
		func(c *Config) { c.MaxRequests = 0 },
	}
	for _, mutate := range cases {
		c := config
		mutate(&c)
		if r, err := OpenSQLiteRuntime(t.Context(), c); !errors.Is(err, servicecall.ErrConfig) {
			if r != nil {
				r.Shutdown(t.Context())
			}
			t.Fatal("accepted reserved wiring", err)
		}
	}
}
