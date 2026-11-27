package quictunnel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/registry"
)

func TestGuardedQUICRegistrationOwnsUntilNativeCleanup(t *testing.T) {
	for _, fault := range []string{"", "ack", "bind", "commit", "before", "identity", "revoked"} {
		t.Run("fault="+fault, func(t *testing.T) {
			reg, ack := Fixtures(t, true)
			reg.ProtocolMinor, ack.ProtocolMinor = 1, 1
			reg.Capabilities = append(reg.Capabilities, "credential_generation")
			reg.RequiredCapabilities = append(reg.RequiredCapabilities, "credential_generation")
			ack.Capabilities = append(ack.Capabilities, "credential_generation")
			ack.RequiredCapabilities = append(ack.RequiredCapabilities, "credential_generation")
			generation := v1.U64(7)
			reg.CredentialGeneration = &generation
			identity := &url.URL{Scheme: "spiffe", Host: "outgate.test", Path: "/service/" + reg.ServiceID + "/instance/" + reg.InstanceID}
			if fault == "identity" {
				identity = nil
			}
			service, gateway := pairWithIdentity(t, true, v1.QUICALPN, identity)
			tlsState := gateway.ConnectionState().TLS
			cert := tlsState.PeerCertificates[0]
			spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			config := controlstate.Config{Path: filepath.Join(t.TempDir(), "control.db"), Epoch: [32]byte{1}, Services: map[string][]string{reg.ServiceID: reg.Paths}}
			must(t, controlstate.Initialize(t.Context(), config))
			store, err := controlstate.Open(t.Context(), config)
			must(t, err)
			t.Cleanup(func() { must(t, store.Close()) })
			id, err := uuid.NewV7()
			must(t, err)
			issued, err := store.IssueGrant(t.Context(), controlstate.Change{OperationID: id.String(), Actor: "deployer", ExpectedRevision: 1, Reason: "QUIC admission integration"}, controlstate.GrantBinding{ServiceID: reg.ServiceID, InstanceID: reg.InstanceID, Version: reg.Version, Paths: reg.Paths, Mounts: reg.Mounts, PathMode: reg.PathMode, RewriteMountHeaders: reg.RewriteMountHeaders, SPKI: hex.EncodeToString(spki[:]), ArtifactDigest: "sha256:" + strings.Repeat("a", 64), ExpiresAt: time.Now().Add(30 * time.Minute), CredentialGeneration: 7})
			must(t, err)
			routes, err := registry.New(registry.Config{Services: map[string]registry.ServiceConfig{reg.ServiceID: {AllowedPaths: reg.Paths, Rollout: registry.Rollout{Stable: reg.Version}}}})
			must(t, err)
			var before, commits, releases atomic.Int32
			guarded, err := GuardRegistration(RegistrationGuard{Store: store, TrustDomain: "outgate.test", Before: func(context.Context, tls.ConnectionState) error {
				before.Add(1)
				if fault == "before" {
					return controlstate.ErrUnavailable
				}
				return nil
			}, Commit: func(ctx context.Context, _ tls.ConnectionState, received v1.Register, lease *controlstate.RegistrationLease) (Binding, error) {
				commits.Add(1)
				if fault == "commit" {
					return Binding{}, controlstate.ErrUnavailable
				}
				// Only the registry persistence callback is synthetic. TLS, credential,
				// generation commit, ownership and native QUIC lifecycle are real here.
				registered, err := routes.RegisterAuthorized(received, registry.QUIC)
				if err != nil {
					return Binding{}, err
				}
				ack.RouteRevision = v1.U64(registered.RouteRevision)
				ack.Paths = nil
				for path, state := range registered.Paths {
					ack.Paths = append(ack.Paths, v1.RegisterAckPath{Path: path, State: string(state)})
				}
				if fault == "ack" {
					ack.RouteRevision++
				}
				if fault == "bind" {
					_, err := routes.BindTransport(registered.Session, received, registry.QUIC)
					if err != nil {
						return Binding{}, err
					}
				}

				if fault == "revoked" {
					op, err := uuid.NewV7()
					if err != nil {
						return Binding{}, err
					}
					rev, err := store.Revision(ctx)
					if err != nil {
						return Binding{}, err
					}
					_, err = store.Revoke(ctx, controlstate.Command{OperationID: op.String(), Actor: "security-admin", ExpectedRevision: rev, Reason: "revoke during registry commit", Target: controlstate.Target{Kind: "grant_id", ServiceID: reg.ServiceID, Value: issued.Record.GrantID}})
					if err != nil {
						return Binding{}, err
					}
				}
				return Binding{Session: registered.Session, Ack: ack, SecurityReady: true, Release: func() {
					releases.Add(1)
					if gateway.Context().Err() == nil {
						t.Error("ownership released before QUIC close")
					}
					if err := store.Close(); !errors.Is(err, controlstate.ErrInstanceInUse) {
						t.Error("store closed during lease cleanup", err)
					}
					_ = routes.Disconnect(registered.Session)
				}}, nil
			}})
			must(t, err)
			type result struct {
				session *BoundSession
				err     error
			}
			accepted := make(chan result, 1)
			go func() {
				s, err := AcceptBound(t.Context(), gateway, routes, BoundOptions{}, guarded)
				accepted <- result{s, err}
			}()
			carrier, received, openErr := quiccontrol.Open(t.Context(), service, quiccontrol.Options{}, []byte(issued.DeploymentGrant), reg)
			outcome := await(t, accepted)
			if fault != "" {
				if openErr == nil || outcome.err == nil {
					if carrier != nil {
						_ = carrier.Close()
					}
					if outcome.session != nil {
						_ = outcome.session.Close(t.Context())
					}
					t.Fatal("invalid admission accepted", fault)
				}
				if (fault == "ack" || fault == "bind" || fault == "revoked") && releases.Load() != 1 {
					t.Fatal("failed ack/bind lost admission release")
				}
			} else {
				must(t, openErr)
				must(t, outcome.err)
				if received.CredentialGeneration == nil || *received.CredentialGeneration != 7 || received.CredentialExpiresAt == nil || *received.CredentialExpiresAt != issued.Record.ExpiresAt.Unix() {
					t.Fatal("guard did not bind ack generation/expiry")
				}
				p := controlstate.GrantPeer{ServiceID: reg.ServiceID, InstanceID: reg.InstanceID, SPKI: hex.EncodeToString(spki[:]), CertificateSerial: cert.SerialNumber.Text(16)}
				if _, err := store.AcquireRegistration(t.Context(), issued.DeploymentGrant, p, reg); !errors.Is(err, controlstate.ErrInstanceInUse) {
					t.Fatal("live QUIC session lost lease", err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				must(t, outcome.session.Close(ctx))
				if releases.Load() != 1 {
					t.Fatal("native cleanup did not release exactly once")
				}
			}
			if before.Load() != 1 {
				t.Fatal("pre-admission gate was bypassed")
			}
			if (fault == "before" || fault == "identity") && commits.Load() != 0 {
				t.Fatal("unverified peer reached registry commit")
			}
			must(t, store.Close()) // success proves every error path released ownership
		})
	}
}

func TestGuardRegistrationErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		err   error
		code  string
		retry bool
	}{
		{controlstate.ErrDenied, "auth_failed", false}, {controlstate.ErrInstanceInUse, "duplicate_instance", true},
		{controlstate.ErrRegistrationQuota, "quota_exceeded", true}, {registry.ErrPathForbidden, "path_forbidden", false},
		{registry.ErrPathConflict, "path_conflict", false}, {registry.ErrInvalid, "invalid_register", false},
	} {
		var rejected *quiccontrol.Rejection
		if !errors.As(registrationRejection(tc.err), &rejected) || rejected.Nack.Code != tc.code || rejected.Nack.Retryable != tc.retry {
			t.Fatal("wrong registration retry classification", tc.code)
		}
		must(t, rejected.Nack.Validate())
	}
	if registrationRejection(controlstate.ErrUnavailable) != controlstate.ErrUnavailable {
		t.Fatal("opaque storage error was reclassified")
	}
}
