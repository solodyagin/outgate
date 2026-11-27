package controlstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"testing"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/registry"
)

func registryConfigs(t *testing.T) (Config, registry.Config) {
	t.Helper()
	c := configuration(t)
	c.Services = map[string][]string{"api": {"/api"}}
	return c, registry.Config{Services: map[string]registry.ServiceConfig{"api": {
		AllowedPaths: []string{"/api"}, Rollout: registry.Rollout{Stable: "v1"},
	}}}
}

func registryData(t *testing.T, r *registry.Registry) []byte {
	t.Helper()
	data, err := r.MarshalSnapshot()
	must(t, err)
	return data
}

func registryRegister(t *testing.T, r *registry.Registry) *registry.Session {
	t.Helper()
	reg := v1.Register{
		Type: "register", ProtocolVersion: 1, ServiceID: "api", InstanceID: "one", Version: "v1",
		Paths: []string{"/api"}, PathMode: "preserve", MaxConcurrentRequests: 100,
		Capabilities: v1.BaselineCapabilities(), RequiredCapabilities: v1.BaselineCapabilities(),
	}
	registered, err := r.RegisterAuthorized(reg, registry.QUIC)
	must(t, err)
	return registered.Session
}

func bootstrapRegistry(t *testing.T, s *Store, cfg registry.Config) *registry.Registry {
	t.Helper()
	r, err := registry.New(cfg)
	must(t, err)
	revision, err := s.Revision(t.Context())
	must(t, err)
	committed, err := s.CommitRegistry(t.Context(), change(t, revision), cfg, registryData(t, r), nil)
	must(t, err)
	if committed.Revision != revision+1 || committed.RegistryRevision != 0 {
		t.Fatal("invalid bootstrap receipt")
	}
	return r
}

func TestRegistryCommitRestartRetryAndColdRecovery(t *testing.T) {
	c, cfg := registryConfigs(t)
	s := fixture(t, c)
	_, err := s.LoadRegistry(t.Context(), cfg, 0)
	if !errors.Is(err, ErrRegistryUninitialized) {
		t.Fatal("implicit bootstrap", err)
	}
	r, err := registry.New(cfg)
	must(t, err)
	boot, data := change(t, 1), registryData(t, r)
	first, err := s.CommitRegistry(t.Context(), boot, cfg, data, nil)
	must(t, err)
	session := registryRegister(t, r)
	previous := uint64(0)
	_, err = s.CommitRegistry(t.Context(), change(t, 2), cfg, registryData(t, r), &previous)
	must(t, err)
	must(t, r.SetReady(session, true))
	must(t, r.ActivateAuthorized("api", "/api", r.Revision()))
	previous = 1
	activate := change(t, 3)
	activeData := registryData(t, r)
	active, err := s.CommitRegistry(t.Context(), activate, cfg, activeData, &previous)
	must(t, err)
	_, err = s.Revoke(t.Context(), command(t, Target{Kind: "service", ServiceID: "other"}, 4))
	must(t, err)
	got, err := s.LoadRegistry(t.Context(), cfg, 5)
	must(t, err)
	if got.Revision != 5 || got.Commit != active || !bytes.Equal(got.Data, activeData) {
		t.Fatal("lost revision binding")
	}
	got.Data[0] = '!'
	_, err = s.LoadRegistry(t.Context(), cfg, 6)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("ignored independent watermark", err)
	}
	events, err := s.Events(t.Context(), 0, 200)
	must(t, err)
	if len(events) != 4 || events[2].Action != registryAction || events[2].Revision != "4" {
		t.Fatal("missing atomic audit")
	}
	for _, event := range events[:3] {
		encoded, err := json.Marshal(event)
		must(t, err)
		if bytes.Contains(encoded, []byte("/api")) || bytes.Contains(encoded, []byte("payload")) {
			t.Fatal("snapshot leaked into outbox")
		}
	}
	must(t, s.Acknowledge(t.Context(), activate.OperationID))
	must(t, s.Close())
	reopened, err := Open(t.Context(), c)
	must(t, err)
	defer reopened.Close()
	got, err = reopened.LoadRegistry(t.Context(), cfg, 5)
	must(t, err)
	recovered, err := registry.RestoreSnapshot(cfg, got.Data)
	must(t, err)
	if decision := recovered.Lookup("/api/work", "", nil); decision.Status != http.StatusServiceUnavailable || decision.Upstream {
		t.Fatal("active route lost during restart")
	}
	for _, retry := range []struct {
		change   Change
		data     []byte
		expected *uint64
		want     RegistryCommit
	}{
		{boot, data, nil, first}, {activate, activeData, &previous, active},
	} {
		result, err := reopened.CommitRegistry(t.Context(), retry.change, cfg, retry.data, retry.expected)
		must(t, err)
		if result != retry.want {
			t.Fatal("retry changed receipt")
		}
	}
	modified := boot
	modified.Actor = "other-admin"
	_, err = reopened.CommitRegistry(t.Context(), modified, cfg, data, nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatal("accepted actor/key reuse", err)
	}
	assertRevision(t, reopened, 5)
}

func TestRegistryOutboxRollbackAndRevisionCAS(t *testing.T) {
	c, cfg := registryConfigs(t)
	c.MaxOutboxEvents = 1
	s := fixture(t, c)
	r := bootstrapRegistry(t, s, cfg)
	registryRegister(t, r)
	previous := uint64(0)
	cmd := change(t, 2)
	_, err := s.CommitRegistry(t.Context(), cmd, cfg, registryData(t, r), &previous)
	if !errors.Is(err, ErrOutboxFull) {
		t.Fatal("published without outbox", err)
	}
	got, err := s.LoadRegistry(t.Context(), cfg, 2)
	must(t, err)
	if got.Commit.RegistryRevision != 0 {
		t.Fatal("rollback changed snapshot")
	}
	assertRevision(t, s, 2)
	var count int
	must(t, s.db.QueryRowContext(t.Context(), "SELECT count(*) FROM control_operations WHERE id=?", cmd.OperationID).Scan(&count))
	if count != 0 {
		t.Fatal("failed commit retained operation")
	}
	events, err := s.Events(t.Context(), 0, 1)
	must(t, err)
	must(t, s.Acknowledge(t.Context(), events[0].OperationID))
	_, err = s.CommitRegistry(t.Context(), cmd, cfg, registryData(t, r), &previous)
	must(t, err)
	// A stale registry CAS must fail even when the global control CAS is current.
	_, err = s.CommitRegistry(t.Context(), change(t, 3), cfg, registryData(t, r), &previous)
	if !errors.Is(err, ErrConflict) {
		t.Fatal("ignored registry CAS", err)
	}
	// A new bootstrap must never reset initialized ownership.
	empty, err := registry.New(cfg)
	must(t, err)
	_, err = s.CommitRegistry(t.Context(), change(t, 3), cfg, registryData(t, empty), nil)
	if !errors.Is(err, ErrConflict) {
		t.Fatal("reset initialized registry", err)
	}
	assertRevision(t, s, 3)
}

func TestConcurrentRegistryCommitChoosesOneOperation(t *testing.T) {
	c, cfg := registryConfigs(t)
	s := fixture(t, c)
	r := bootstrapRegistry(t, s, cfg)
	registryRegister(t, r)
	data := registryData(t, r)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		cmd := change(t, 2)
		wg.Add(1)
		go func() {
			defer wg.Done()
			previous := uint64(0)
			_, err := s.CommitRegistry(t.Context(), cmd, cfg, data, &previous)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatal("nonatomic CAS", success, conflicts)
	}
	assertRevision(t, s, 3)
}

func TestRegistryReadRejectsLostCorruptAndRolledBackRow(t *testing.T) {
	for name, corrupt := range map[string]func(*testing.T, *Store, RegistrySnapshot){
		"missing": func(t *testing.T, s *Store, old RegistrySnapshot) {
			_, err := s.db.ExecContext(t.Context(), "DELETE FROM registry_snapshot")
			must(t, err)
		},
		"payload": func(t *testing.T, s *Store, old RegistrySnapshot) {
			_, err := s.db.ExecContext(t.Context(), "UPDATE registry_snapshot SET payload=CAST('{}' AS BLOB)")
			must(t, err)
		},
		"sentinel": func(t *testing.T, s *Store, old RegistrySnapshot) {
			_, err := s.db.ExecContext(t.Context(), "UPDATE registry_snapshot SET operation_id='',revision='0',payload=X''")
			must(t, err)
		},
		"rollback": func(t *testing.T, s *Store, old RegistrySnapshot) {
			var operation string
			must(t, s.db.QueryRowContext(t.Context(), "SELECT id FROM control_operations WHERE revision=?", "2").Scan(&operation))
			_, err := s.db.ExecContext(t.Context(), "UPDATE registry_snapshot SET operation_id=?,revision='2',payload=?", operation, old.Data)
			must(t, err)
		},
		"result": func(t *testing.T, s *Store, old RegistrySnapshot) {
			_, err := s.db.ExecContext(t.Context(), "UPDATE security_results SET result=CAST('{}' AS BLOB) WHERE id=(SELECT operation_id FROM registry_snapshot)")
			must(t, err)
		},
		"revision": func(t *testing.T, s *Store, old RegistrySnapshot) {
			_, err := s.db.ExecContext(t.Context(), "UPDATE registry_snapshot SET revision='03'")
			must(t, err)
		},
		"oversized": func(t *testing.T, s *Store, old RegistrySnapshot) {
			_, err := s.db.ExecContext(t.Context(), "PRAGMA ignore_check_constraints=ON")
			must(t, err)
			_, err = s.db.ExecContext(t.Context(), "UPDATE registry_snapshot SET payload=zeroblob(1048577)")
			must(t, err)
			_, err = s.db.ExecContext(t.Context(), "PRAGMA ignore_check_constraints=OFF")
			must(t, err)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, cfg := registryConfigs(t)
			s := fixture(t, c)
			r := bootstrapRegistry(t, s, cfg)
			old, err := s.LoadRegistry(t.Context(), cfg, 2)
			must(t, err)
			registryRegister(t, r)
			previous := uint64(0)
			_, err = s.CommitRegistry(t.Context(), change(t, 2), cfg, registryData(t, r), &previous)
			must(t, err)
			corrupt(t, s, old)
			got, err := s.LoadRegistry(t.Context(), cfg, 0)
			if !errors.Is(err, ErrUnavailable) || got.Data != nil {
				t.Fatal("published damaged state", err)
			}
			must(t, s.Close())
			if opened, err := Open(t.Context(), c); err == nil {
				opened.Close()
				t.Fatal("Open accepted damaged registry")
			}
		})
	}
}

func TestRegistryRejectsInvalidCandidateAndPermissions(t *testing.T) {
	c, cfg := registryConfigs(t)
	s := fixture(t, c)
	r := bootstrapRegistry(t, s, cfg)
	registryRegister(t, r)
	data := registryData(t, r)
	_, err := s.CommitRegistry(t.Context(), change(t, 2), cfg, data, nil)
	if !errors.Is(err, ErrConfig) {
		t.Fatal("nonempty bootstrap", err)
	}
	previous := uint64(0)
	for _, invalid := range [][]byte{nil, []byte("{}"), bytes.Repeat([]byte{'x'}, registry.MaxSnapshotBytes+1)} {
		_, err := s.CommitRegistry(t.Context(), change(t, 2), cfg, invalid, &previous)
		if !errors.Is(err, ErrConfig) {
			t.Fatal("invalid snapshot committed", err)
		}
	}
	changed := cfg
	changed.Services = map[string]registry.ServiceConfig{"api": {AllowedPaths: []string{"/other"}, Rollout: registry.Rollout{Stable: "v1"}}}
	_, err = s.LoadRegistry(t.Context(), changed, 0)
	if !errors.Is(err, ErrConfig) {
		t.Fatal("mismatched trusted allowlist", err)
	}
	_, err = s.CommitRegistry(t.Context(), change(t, 2), changed, data, &previous)
	if !errors.Is(err, ErrConfig) {
		t.Fatal("changed permission allowed", err)
	}
	assertRevision(t, s, 2)
}

func TestRegistryRetryBindsCompleteRequest(t *testing.T) {
	c, cfg := registryConfigs(t)
	s := fixture(t, c)
	r := bootstrapRegistry(t, s, cfg)
	registryRegister(t, r)
	data, cmd, previous := registryData(t, r), change(t, 2), uint64(0)
	want, err := s.CommitRegistry(t.Context(), cmd, cfg, data, &previous)
	must(t, err)
	for _, modify := range []func(*Change){
		func(c *Change) { c.Actor = "other-admin" },
		func(c *Change) { c.Reason = "different reason" },
		func(c *Change) { c.ExpectedRevision = 3 },
	} {
		modified := cmd
		modify(&modified)
		_, err := s.CommitRegistry(t.Context(), modified, cfg, data, &previous)
		if !errors.Is(err, ErrConflict) {
			t.Fatal("reused operation context", err)
		}
	}
	different := bytes.Replace(data, []byte(`"quic"`), []byte(`"wss"`), 1)
	_, err = s.CommitRegistry(t.Context(), cmd, cfg, different, &previous)
	if !errors.Is(err, ErrConflict) {
		t.Fatal("reused operation with different snapshot", err)
	}
	got, err := s.LoadRegistry(t.Context(), cfg, 3)
	must(t, err)
	if got.Commit != want {
		t.Fatal("key conflict modified snapshot")
	}
}

func TestRegistryLoadValidatesSemanticsBeyondDigest(t *testing.T) {
	c, cfg := registryConfigs(t)
	s := fixture(t, c)
	bootstrapRegistry(t, s, cfg)
	got, err := s.LoadRegistry(t.Context(), cfg, 2)
	must(t, err)
	invalid := []byte("{}\n")
	receipt := got.Commit
	receipt.Digest = fmtDigest(sha256.Sum256(invalid))
	encoded, err := json.Marshal(receipt)
	must(t, err)
	_, err = s.db.ExecContext(t.Context(), "UPDATE registry_snapshot SET payload=?", invalid)
	must(t, err)
	_, err = s.db.ExecContext(t.Context(), "UPDATE security_results SET result=? WHERE id=(SELECT operation_id FROM registry_snapshot)", encoded)
	must(t, err)
	if state, err := s.LoadRegistry(t.Context(), cfg, 2); !errors.Is(err, ErrUnavailable) || state.Data != nil {
		t.Fatal("hash bypassed semantic checks", err)
	}
}

func TestRegistryCommitSurvivesAbruptExitBeforeResponse(t *testing.T) {
	if os.Getenv("OUTGATE_REGISTRY_CRASH_HELPER") == "1" {
		c := Config{Path: os.Getenv("OUTGATE_REGISTRY_PATH"), Epoch: [32]byte{1}, Services: map[string][]string{"api": {"/api"}}}
		cfg := registry.Config{Services: map[string]registry.ServiceConfig{"api": {AllowedPaths: []string{"/api"}, Rollout: registry.Rollout{Stable: "v1"}}}}
		s, err := Open(context.Background(), c)
		if err != nil {
			os.Exit(1)
		}
		var cmd Change
		if json.Unmarshal([]byte(os.Getenv("OUTGATE_REGISTRY_CHANGE")), &cmd) != nil {
			os.Exit(2)
		}
		previous := uint64(1)
		_, err = s.CommitRegistry(context.Background(), cmd, cfg, []byte(os.Getenv("OUTGATE_REGISTRY_DATA")), &previous)
		if err != nil {
			os.Exit(3)
		}
		os.Exit(0) // no response and no deferred close/checkpoint
	}
	c, cfg := registryConfigs(t)
	s := fixture(t, c)
	r := bootstrapRegistry(t, s, cfg)
	session := registryRegister(t, r)
	previous := uint64(0)
	_, err := s.CommitRegistry(t.Context(), change(t, 2), cfg, registryData(t, r), &previous)
	must(t, err)
	must(t, r.SetReady(session, true))
	must(t, r.ActivateAuthorized("api", "/api", r.Revision()))
	data, cmd := registryData(t, r), change(t, 3)
	encoded, err := json.Marshal(cmd)
	must(t, err)
	must(t, s.Close())
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRegistryCommitSurvivesAbruptExitBeforeResponse$")
	child.Env = append(os.Environ(), "OUTGATE_REGISTRY_CRASH_HELPER=1", "OUTGATE_REGISTRY_PATH="+c.Path, "OUTGATE_REGISTRY_CHANGE="+string(encoded), "OUTGATE_REGISTRY_DATA="+string(data))
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("crash helper: %v (%s)", err, output)
	}
	reopened, err := Open(t.Context(), c)
	must(t, err)
	defer reopened.Close()
	previous = 1
	result, err := reopened.CommitRegistry(t.Context(), cmd, cfg, data, &previous)
	must(t, err)
	if result.Revision != 4 || result.RegistryRevision != 2 {
		t.Fatal("lost committed response")
	}
	got, err := reopened.LoadRegistry(t.Context(), cfg, 4)
	must(t, err)
	if got.Commit != result || !bytes.Equal(got.Data, data) {
		t.Fatal("lost committed snapshot")
	}
	events, err := reopened.Events(t.Context(), 0, 200)
	must(t, err)
	if len(events) != 3 {
		t.Fatal("retry duplicated audit event")
	}
}
