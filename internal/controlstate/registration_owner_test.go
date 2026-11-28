package controlstate

import (
	"bytes"
	"errors"
	"net/http"
	"sync"
	"testing"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/registry"
)

func registrationOwnerFixture(t *testing.T) (*Store, registry.Config, *RegistrationOwner) {
	t.Helper()
	c := securityConfig(t)
	cfg := registry.Config{FrontendService: c.RootFrontend, Services: map[string]registry.ServiceConfig{}}
	for id, paths := range c.Services {
		cfg.Services[id] = registry.ServiceConfig{AllowedPaths: paths, Rollout: registry.Rollout{Stable: "1.0.0"}}
	}
	s := fixture(t, c)
	bootstrapRegistry(t, s, cfg)
	owner, err := OpenRegistrationOwner(t.Context(), s, cfg, 2)
	must(t, err)
	return s, cfg, owner
}

func ownerLease(t *testing.T, s *Store, instance string) (*RegistrationLease, v1.Register) {
	t.Helper()
	issued, peer, reg := registrationGrant(t, s, 7, instance)
	lease, err := s.AcquireRegistration(t.Context(), issued.DeploymentGrant, peer, reg)
	must(t, err)
	t.Cleanup(lease.Release)
	return lease, reg
}

func TestRegistrationOwnerPersistsBeforeLivePublication(t *testing.T) {
	s, cfg, owner := registrationOwnerFixture(t)
	routes := owner.Routes()
	lease, reg := ownerLease(t, s, "reports-1")
	// The exported copy of metadata cannot change the private admission identity.
	lease.Grant.GrantID = "changed"
	lease.Grant.Paths = []string{"/forged"}
	before, err := s.Revision(t.Context())
	must(t, err)
	result, err := owner.Register(t.Context(), lease, reg, registry.QUIC)
	must(t, err)
	if result.Session == nil || routes != owner.Routes() || result.Paths["/api/v1"] != registry.Pending {
		t.Fatal("invalid publication")
	}
	durable, err := s.LoadRegistry(t.Context(), cfg, before+1)
	must(t, err)
	if durable.Revision != before+1 || durable.Commit.RegistryRevision != 1 {
		t.Fatal("missing snapshot/control revision")
	}
	data, err := routes.MarshalSnapshot()
	must(t, err)
	if !bytes.Equal(data, durable.Data) {
		t.Fatal("live state differs from committed candidate")
	}
	_, err = routes.BindTransport(result.Session, reg, registry.QUIC)
	must(t, err)
	must(t, routes.SetReady(result.Session, true))
	nextLease, nextReg := ownerLease(t, s, "reports-2")
	next, err := owner.Register(t.Context(), nextLease, nextReg, registry.QUIC)
	must(t, err)
	must(t, routes.CanDispatch(result.Session))
	if next.Session == result.Session {
		t.Fatal("new registration reused a handle")
	}
	recovered, err := OpenRegistrationOwner(t.Context(), s, cfg, owner.minimum)
	must(t, err)
	versions, err := recovered.Routes().Versions(reg.ServiceID)
	must(t, err)
	if len(versions) != 1 || versions[0].Instances != 0 {
		t.Fatal("cold recovery restored live sessions")
	}
	must(t, routes.Disconnect(result.Session))
	must(t, routes.Disconnect(next.Session))
}

func TestRegistrationOwnerRejectsStaleOrMismatchedLease(t *testing.T) {
	for _, fault := range []string{"released", "forged", "binding", "revoked", "generation", "foreign_store"} {
		t.Run(fault, func(t *testing.T) {
			s, cfg, owner := registrationOwnerFixture(t)
			lease, reg := ownerLease(t, s, "reports-1")
			switch fault {
			case "released":
				lease.Release()
			case "forged":
				lease = &RegistrationLease{store: lease.store, peer: lease.peer, instance: lease.instance, grantID: lease.grantID}
			case "binding":
				reg.Version = "different"
			case "revoked":
				revision, err := s.Revision(t.Context())
				must(t, err)
				_, err = s.Revoke(t.Context(), command(t, Target{Kind: "service", ServiceID: reg.ServiceID}, revision))
				must(t, err)
			case "generation":
				generation := v1.U64(8)
				reg.CredentialGeneration = &generation
			case "foreign_store":
				other, _, _ := registrationOwnerFixture(t)
				lease, reg = ownerLease(t, other, "reports-1")
			}
			before, err := s.LoadRegistry(t.Context(), cfg, 0)
			must(t, err)
			result, err := owner.Register(t.Context(), lease, reg, registry.QUIC)
			if !errors.Is(err, ErrDenied) || result.Session != nil {
				t.Fatal("accepted invalid lease", err)
			}
			after, err := s.LoadRegistry(t.Context(), cfg, 0)
			must(t, err)
			if before.Revision != after.Revision || !bytes.Equal(before.Data, after.Data) {
				t.Fatal("denied registration changed durable state")
			}
			// A transaction-level denial conservatively closes the barrier; a foreign
			// store is rejected before entering publication.
			if fault != "foreign_store" {
				if owner.Routes().Lookup("/app", "", nil).Status != http.StatusServiceUnavailable {
					t.Fatal("uncertain failure left dispatch open")
				}
				must(t, owner.Resync(t.Context()))
			}
		})
	}
}

func TestRegistrationOwnerOutboxRollbackResyncAndRetry(t *testing.T) {
	s, cfg, owner := registrationOwnerFixture(t)
	lease, reg := ownerLease(t, s, "reports-1")
	before, err := s.LoadRegistry(t.Context(), cfg, 0)
	must(t, err)
	var operations int
	must(t, s.db.QueryRow("SELECT count(*) FROM control_operations").Scan(&operations))
	limit := s.config.MaxOutboxEvents
	s.config.MaxOutboxEvents = 1
	_, err = owner.Register(t.Context(), lease, reg, registry.QUIC)
	if !errors.Is(err, ErrOutboxFull) {
		t.Fatal("published without audit capacity", err)
	}
	// No snapshot, revision, result or operation may survive a rolled-back outbox.
	after, err := s.LoadRegistry(t.Context(), cfg, 0)
	must(t, err)
	var current int
	must(t, s.db.QueryRow("SELECT count(*) FROM control_operations").Scan(&current))
	if current != operations || before.Revision != after.Revision || !bytes.Equal(before.Data, after.Data) {
		t.Fatal("partial registration commit")
	}
	_, err = owner.Register(t.Context(), lease, reg, registry.QUIC)
	if !errors.Is(err, registry.ErrPublicationUnavailable) {
		t.Fatal("retried before resync", err)
	}
	must(t, owner.Resync(t.Context()))
	s.config.MaxOutboxEvents = limit
	registered, err := owner.Register(t.Context(), lease, reg, registry.QUIC)
	must(t, err)
	must(t, owner.Routes().Disconnect(registered.Session))
}

func TestRegistrationOwnerRecoveryWatermarkAndConfiguration(t *testing.T) {
	c, cfg := registryConfigs(t)
	s := fixture(t, c)
	if _, err := OpenRegistrationOwner(t.Context(), s, cfg, 0); !errors.Is(err, ErrRegistryUninitialized) {
		t.Fatal("implicit bootstrap", err)
	}
	bootstrapRegistry(t, s, cfg)
	if _, err := OpenRegistrationOwner(t.Context(), s, cfg, 3); !errors.Is(err, ErrUnavailable) {
		t.Fatal("ignored watermark", err)
	}
	owner, err := OpenRegistrationOwner(t.Context(), s, cfg, 2)
	must(t, err)
	cfg.Services["api"].AllowedPaths[0] = "/changed"
	if owner.config.Services["api"].AllowedPaths[0] != "/api" {
		t.Fatal("mutable configuration escaped")
	}
	if _, err := OpenRegistrationOwner(t.Context(), nil, cfg, 0); !errors.Is(err, ErrConfig) {
		t.Fatal("nil store accepted", err)
	}
}

func TestConcurrentRegistrationOwner(t *testing.T) {
	s, cfg, owner := registrationOwnerFixture(t)
	type admission struct {
		lease *RegistrationLease
		reg   v1.Register
	}
	var admissions []admission
	for _, id := range []string{"one", "two", "three", "four"} {
		lease, reg := ownerLease(t, s, id)
		admissions = append(admissions, admission{lease, reg})
	}
	var wg sync.WaitGroup
	failures := make(chan error, len(admissions))
	for _, a := range admissions {
		wg.Go(func() {
			_, err := owner.Register(t.Context(), a.lease, a.reg, registry.QUIC)
			if err != nil {
				failures <- err
			}
		})
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	durable, err := s.LoadRegistry(t.Context(), cfg, 0)
	must(t, err)
	if durable.Commit.RegistryRevision != uint64(len(admissions)) || owner.Routes().Revision() != durable.Commit.RegistryRevision {
		t.Fatal("lost concurrent registration")
	}
}

func TestRegistrationOwnerResyncAfterCommittedLostResult(t *testing.T) {
	s, cfg, owner := registrationOwnerFixture(t)
	lease, reg := ownerLease(t, s, "reports-1")
	revision, err := s.Revision(t.Context())
	must(t, err)
	lost := errors.New("lost commit result")
	result, err := owner.Routes().CommitRegistrationAuthorized(reg, registry.QUIC, func(data []byte, previous uint64) error {
		_, err := s.CommitRegistry(t.Context(), change(t, revision), cfg, data, &previous)
		if err != nil {
			return err
		}
		return lost
	})
	if !errors.Is(err, lost) || result.Session != nil {
		t.Fatal("failed admission returned a live session", err)
	}
	must(t, owner.Resync(t.Context()))
	if owner.minimum != revision+1 || owner.Routes().Revision() != 1 {
		t.Fatal("resync lost confirmed registry state")
	}
	versions, err := owner.Routes().Versions(reg.ServiceID)
	must(t, err)
	if len(versions) != 1 || versions[0].Instances != 0 {
		t.Fatal("resync acknowledged a failed admission")
	}
	// A fresh explicit registration may reconnect using the still-owned lease.
	// Actual Guard users retain it until native cleanup before reconnecting.
	fresh, err := owner.Register(t.Context(), lease, reg, registry.QUIC)
	must(t, err)
	must(t, owner.Routes().Disconnect(fresh.Session))
}

func TestRegistrationOwnerResyncRejectsRollbackAndCorruption(t *testing.T) {
	s, _, owner := registrationOwnerFixture(t)
	lease, reg := ownerLease(t, s, "reports-1")
	revision, err := s.Revision(t.Context())
	must(t, err)
	s.config.MaxOutboxEvents = 1
	_, err = owner.Register(t.Context(), lease, reg, registry.QUIC)
	if !errors.Is(err, ErrOutboxFull) {
		t.Fatal("expected failed commit", err)
	}
	// The owner's floor includes the admitted generation even when route commit
	// failed. A lower global revision cannot lift its publication barrier.
	_, err = s.db.Exec("UPDATE control_metadata SET revision=? WHERE id=1", revision-1)
	must(t, err)
	if err := owner.Resync(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("accepted rollback", err)
	}
	_, err = s.db.Exec("UPDATE control_metadata SET revision=? WHERE id=1", revision)
	must(t, err)
	var data []byte
	must(t, s.db.QueryRow("SELECT payload FROM registry_snapshot WHERE id=1").Scan(&data))
	_, err = s.db.Exec("UPDATE registry_snapshot SET payload=? WHERE id=1", []byte("corrupt"))
	must(t, err)
	if err := owner.Resync(t.Context()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("accepted corrupt snapshot", err)
	}
	if got := owner.Routes().Lookup("/app", "", nil); got.Status != http.StatusServiceUnavailable {
		t.Fatal("failed resync opened fallback")
	}
	_, err = s.db.Exec("UPDATE registry_snapshot SET payload=? WHERE id=1", data)
	must(t, err)
	must(t, owner.Resync(t.Context()))
}
