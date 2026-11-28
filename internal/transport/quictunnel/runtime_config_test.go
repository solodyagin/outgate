package quictunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/solodyagin/outgate/internal/controlstate"
)

func TestRuntimeConfigurationFailsClosedAndReleasesOpenedStores(t *testing.T) {
	f := runtimeFixtureConfig(t)
	for _, fault := range []string{"roots", "key", "nil_key", "ed25519_key", "client_eku", "der", "owner_override", "security_override", "handshake_limit", "memory_limit", "native_buffer", "window", "missing_replay", "uninitialized_registry"} {
		t.Run(fault, func(t *testing.T) {
			config, limits := f.config, f.limits
			switch fault {
			case "roots":
				config.ClientRoots = x509.NewCertPool()
			case "key":
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				must(t, err)
				config.Certificate.PrivateKey = key
			case "nil_key":
				config.Certificate.PrivateKey = (*ecdsa.PrivateKey)(nil)
			case "ed25519_key":
				config.Certificate.PrivateKey = ed25519.PrivateKey{1}
			case "client_eku":
				config.Certificate = f.client.Certificates[0]
			case "der":
				config.Certificate.Certificate = [][]byte{[]byte("invalid")}
			case "owner_override":
				config.Admission.Owner = &controlstate.RegistrationOwner{}
			case "security_override":
				config.Admission.Security = fakeRuntimeSecurity
			case "handshake_limit":
				limits.HandshakeTimeout = 6 * time.Second
			case "memory_limit":
				limits.BufferBytes = 1
			case "native_buffer":
				config.Admission.Policy.Limits.BufferBytes = 1
			case "window":
				limits.StreamReceiveWindow = 0
			case "missing_replay":
				config.Replay.Path = filepath.Join(t.TempDir(), "missing.db")
			case "uninitialized_registry":
				config.Control.Path = filepath.Join(t.TempDir(), "fresh-control.db")
				must(t, controlstate.Initialize(t.Context(), config.Control))
			}
			runtime, err := OpenSQLiteRuntime(t.Context(), config, limits)
			if err == nil {
				_ = runtime.Shutdown(t.Context())
				t.Fatal("invalid runtime configuration accepted", fault)
			}
			if fault == "missing_replay" || fault == "uninitialized_registry" {
				store, err := controlstate.Open(t.Context(), config.Control)
				must(t, err)
				must(t, store.Close())
			}
		})
	}
}

func TestRuntimeFreezesTLSAndUsesBoundedTransportProfile(t *testing.T) {
	f := runtimeFixtureConfig(t)
	r, err := OpenSQLiteRuntime(t.Context(), f.config, f.limits)
	must(t, err)
	first := r.tls.Certificates[0].Certificate[0][0]
	f.config.Certificate.Certificate[0][0] ^= 1
	if r.tls.Certificates[0].Certificate[0][0] != first {
		t.Fatal("certificate bytes were not detached")
	}
	if r.quic.Allow0RTT || !r.tls.SessionTicketsDisabled || r.quic.MaxIncomingStreams != 1 || r.quic.MaxIncomingUniStreams != 3 || r.quic.MaxConnectionReceiveWindow != f.limits.ConnectionReceiveWindow || r.quic.HandshakeIdleTimeout != 2500*time.Millisecond {
		t.Fatal("unbounded transport profile")
	}
	if err := r.Ready(t.Context()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatal("unstarted runtime ready")
	}
	must(t, r.Shutdown(t.Context()))
}

func fakeRuntimeSecurity(context.Context) (AdmissionSecurity, error) { return AdmissionSecurity{}, nil }
