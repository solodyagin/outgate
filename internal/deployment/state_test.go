package deployment

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/solodyagin/outgate-sdk/replay"
	"github.com/solodyagin/outgate/internal/config"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/gateway"
	"github.com/solodyagin/outgate/internal/registry"
)

func installation() StateIdentity {
	return StateIdentity{ControlEpoch: [32]byte{1}, ReplayEpoch: [32]byte{2}, MinimumControlRevision: 2}
}
func stateDocument(t *testing.T) (*config.Document, map[string]any) {
	t.Helper()
	_, v := fixture(t)
	obj(obj(v, "storage"), "control")["path"] = filepath.Join(t.TempDir(), "control.db")
	obj(obj(v, "storage"), "replay")["path"] = filepath.Join(t.TempDir(), "replay.db")
	return document(t, v), v
}
func TestStateMapping(t *testing.T) {
	doc, _ := stateDocument(t)
	p, err := PlanSQLiteState(doc, installation())
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Configs()
	if err != nil {
		t.Fatal(err)
	}
	if c.Control.Epoch != installation().ControlEpoch || c.Replay.Epoch != installation().ReplayEpoch || c.MinimumControlRevision != 2 || c.Control.Path == c.Replay.Path {
		t.Fatal("installation evidence changed")
	}
	if c.Control.MaxRegistrations != 1000 || c.Registry.MaxTunnels != 1000 || c.Registry.MaxTunnelsPerService != 16 || c.Registry.MaxPathsPerInstance != 32 || c.Registry.MaxVersions != 100 {
		t.Fatal("quotas not mapped")
	}
	if c.Registry.FrontendService != "frontend-service" || c.Registry.FrontendEnabled || c.Control.RootFrontend != "frontend-service" || c.Registry.Development {
		t.Fatal("frontend/security mode")
	}
	ap := c.Registry.Services["reports-service"].ActivePassive
	if ap == nil || ap.Preempt || *ap.HoldDown != 30*time.Second || len(ap.Orders["1.0.0"]) != 3 {
		t.Fatal("active passive mapping")
	}
	if c.Replay.Capacity != 200000 || c.Replay.CallerCapacity != 20000 || c.Replay.AdmittedRPS != 1000 || c.Replay.AdmittedBurst != 2000 || c.Replay.Namespace != "outgate:gateway" {
		t.Fatal("replay mapping")
	}
	// Planning must not create/open any configured state, owner or sidecar.
	for _, path := range []string{c.Control.Path, c.Control.Path + ".owner", c.Replay.Path} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("planner performed IO", err)
		}
	}
	c.Control.Services["my-service"][0] = "/changed"
	paths := c.Registry.Services["my-service"].AllowedPaths
	paths[0] = "/changed"
	ap.Orders["1.0.0"][0] = "changed"
	*ap.HoldDown = 0
	c.Registry.ReservedAPIPrefixes[0] = "/changed"
	c.Registry.SharedPaths[0] = "/changed"
	again, err := p.Configs()
	if err != nil {
		t.Fatal(err)
	}
	if again.Control.Services["my-service"][0] == "/changed" || again.Registry.Services["my-service"].AllowedPaths[0] == "/changed" || again.Registry.Services["reports-service"].ActivePassive.Orders["1.0.0"][0] == "changed" || *again.Registry.Services["reports-service"].ActivePassive.HoldDown != 30*time.Second || again.Registry.SharedPaths[0] == "/changed" {
		t.Fatal("mutable plan")
	}
	for _, v := range []any{p, again} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, v), ".db") {
				t.Fatal("format leaked path")
			}
		}
	}
}
func TestStateDefaultsAndExplicitZeroHold(t *testing.T) {
	_, v := stateDocument(t)
	for _, key := range []string{"max_paths_per_instance", "max_tunnels", "max_versions_per_service"} {
		delete(obj(v, "tunnel"), key)
	}
	delete(obj(obj(v, "security"), "resource_limits"), "tunnels_per_service")
	delete(obj(obj(v, "security"), "rate_limits"), "signed_per_second")
	delete(obj(obj(v, "security"), "rate_limits"), "signed_burst")
	delete(obj(v, "interservice"), "replay_cache_max_entries")
	delete(obj(v, "interservice"), "replay_max_entries_per_caller")
	delete(obj(obj(v, "storage"), "replay"), "recovery_barrier")
	obj(obj(obj(v, "services"), "reports-service"), "instance_routing")["recovery_hold_down"] = "0s"
	p, err := PlanSQLiteState(document(t, v), installation())
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Configs()
	if err != nil {
		t.Fatal(err)
	}
	if c.Registry.MaxTunnels != 1000 || c.Registry.MaxVersions != 100 || c.Registry.MaxTunnelsPerService != 16 || c.Replay.Capacity != 200000 || c.Replay.AdmittedRPS != 1000 || *c.Registry.Services["reports-service"].ActivePassive.HoldDown != 0 {
		t.Fatal("defaults or explicit zero lost")
	}
	obj(v, "routing")["strategy"] = "active_passive"
	for _, id := range []string{"my-service", "frontend-service"} {
		obj(v, "services")[id].(map[string]any)["instance_routing"] = map[string]any{"strategy": "round_robin"}
	}
	if _, err := PlanSQLiteState(document(t, v), installation()); err != nil {
		t.Fatal("per-service strategy override", err)
	}
}
func TestStateProfileRejections(t *testing.T) {
	doc, _ := stateDocument(t)
	for name, change := range map[string]func(map[string]any){
		"barrier":  func(v map[string]any) { obj(obj(v, "storage"), "replay")["recovery_barrier"] = "121s" },
		"relative": func(v map[string]any) { obj(obj(v, "storage"), "control")["path"] = "relative/control.db" },
		"same_file": func(v map[string]any) {
			obj(obj(v, "storage"), "replay")["path"] = obj(obj(v, "storage"), "control")["path"]
		},
		"wal_collision": func(v map[string]any) {
			obj(obj(v, "storage"), "replay")["path"] = obj(obj(v, "storage"), "control")["path"].(string) + "-wal"
		},
		"owner_collision": func(v map[string]any) {
			obj(obj(v, "storage"), "replay")["path"] = obj(obj(v, "storage"), "control")["path"].(string) + ".owner"
		},
		"parent_collision": func(v map[string]any) {
			obj(obj(v, "storage"), "replay")["path"] = filepath.Join(obj(obj(v, "storage"), "control")["path"].(string), "child.db")
		},
		"quota": func(v map[string]any) { obj(v, "tunnel")["max_tunnels"] = 1000001 },
		"ap_interval": func(v map[string]any) {
			obj(obj(obj(obj(v, "services"), "reports-service"), "instance_routing"), "readiness")["interval"] = "6s"
		},
		"ap_threshold": func(v map[string]any) {
			obj(obj(obj(obj(v, "services"), "reports-service"), "instance_routing"), "readiness")["healthy_threshold"] = 4
		},
		"ignored_rr_knob": func(v map[string]any) {
			obj(obj(v, "services"), "my-service")["instance_routing"] = map[string]any{"strategy": "round_robin", "preempt": false}
		},
		"postgres": func(v map[string]any) {
			obj(v, "storage")["control"] = map[string]any{"driver": "postgres", "host": "db.internal", "port": 5432, "database": "outgate", "schema": "control", "user": "runtime", "password_env": "UNUSED_PASSWORD", "sslmode": "verify-full", "ca_file": "unused.pem"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := doc.Values()
			change(v)
			p, err := PlanSQLiteState(document(t, v), installation())
			if p != nil || !errors.Is(err, ErrProfile) || err.Error() != ErrProfile.Error() {
				t.Fatal(p, err)
			}
		})
	}
	for _, identity := range []StateIdentity{{}, {ControlEpoch: [32]byte{1}, ReplayEpoch: [32]byte{1}, MinimumControlRevision: 2}, {ControlEpoch: [32]byte{1}, ReplayEpoch: [32]byte{2}}} {
		if _, err := PlanSQLiteState(doc, identity); !errors.Is(err, ErrProfile) {
			t.Fatal(err)
		}
	}
	if _, err := (*SQLiteStatePlan)(nil).Configs(); !errors.Is(err, ErrProfile) {
		t.Fatal(err)
	}
}
func TestStateBindingRejectsOverrides(t *testing.T) {
	doc, _ := stateDocument(t)
	p, err := PlanSQLiteState(doc, installation())
	if err != nil {
		t.Fatal(err)
	}
	bound, err := p.Bind(gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*gateway.Config){func(c *gateway.Config) { c.Tunnel.Control = bound.Tunnel.Control }, func(c *gateway.Config) { c.Tunnel.Registry = bound.Tunnel.Registry }, func(c *gateway.Config) { c.Tunnel.Replay = bound.Tunnel.Replay }, func(c *gateway.Config) { c.Tunnel.MinimumControlRevision = 2 }} {
		base := gateway.Config{}
		change(&base)
		if _, err := p.Bind(base); !errors.Is(err, ErrProfile) {
			t.Fatal(err)
		}
	}
}

func TestMappedStateRestoresDurableRolloutAndRejectsRollback(t *testing.T) {
	doc, _ := stateDocument(t)
	p, err := PlanSQLiteState(doc, installation())
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Configs()
	if err != nil {
		t.Fatal(err)
	}
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	check(controlstate.Initialize(t.Context(), c.Control))
	store, err := controlstate.Open(t.Context(), c.Control)
	check(err)
	// Explicit provisioning commits a newer policy than the YAML bootstrap value.
	service := c.Registry.Services["my-service"]
	service.Rollout.Stable = "9.0.0"
	c.Registry.Services["my-service"] = service
	reg, err := registry.New(c.Registry)
	check(err)
	data, err := reg.MarshalSnapshot()
	check(err)
	id, err := uuid.NewV7()
	check(err)
	_, err = store.CommitRegistry(t.Context(), controlstate.Change{OperationID: id.String(), Actor: "operator", ExpectedRevision: 1, Reason: "state mapping recovery test"}, c.Registry, data, nil)
	check(err)
	check(store.Close())
	original, err := p.Configs()
	check(err)
	store, err = controlstate.Open(t.Context(), original.Control)
	check(err)
	defer store.Close()
	owner, err := controlstate.OpenRegistrationOwner(t.Context(), store, original.Registry, original.MinimumControlRevision)
	check(err)
	policy, _, err := owner.Routes().Rollout("my-service")
	check(err)
	if policy.Stable != "9.0.0" {
		t.Fatal("durable rollout replaced with YAML", policy)
	}
	if _, err := controlstate.OpenRegistrationOwner(t.Context(), store, original.Registry, 3); err == nil {
		t.Fatal("revision rollback accepted")
	}
	check(store.Close())
	changed := original.Control
	changed.Epoch = [32]byte{3}
	if other, err := controlstate.Open(t.Context(), changed); err == nil {
		other.Close()
		t.Fatal("wrong epoch accepted")
	}
	check(replay.InitializeSQLite(t.Context(), original.Replay))
	replayStore, err := replay.OpenSQLite(t.Context(), original.Replay)
	check(err)
	defer replayStore.Close()
	if _, err := replayStore.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := replayStore.Ready(context.Background()); err == nil {
		t.Fatal("recovery barrier bypassed")
	}
}

func TestStateNondefaultSettings(t *testing.T) {
	_, v := stateDocument(t)
	tunnel := obj(v, "tunnel")
	tunnel["max_paths_per_instance"] = 8
	tunnel["max_tunnels"] = 20
	tunnel["max_versions_per_service"] = 3
	obj(obj(v, "security"), "resource_limits")["tunnels_per_service"] = 4
	rates := obj(obj(v, "security"), "rate_limits")
	rates["signed_per_second"] = 3
	rates["signed_burst"] = 7
	obj(v, "interservice")["replay_cache_max_entries"] = 1000
	obj(v, "interservice")["replay_max_entries_per_caller"] = 100
	obj(obj(v, "storage"), "replay")["recovery_barrier"] = "2m"
	obj(v, "frontend_override")["enabled"] = true
	obj(v, "routing")["reserved_api_prefixes"] = []any{"/api", "/private"}
	rollout := obj(obj(obj(v, "services"), "my-service"), "rollout")
	rollout["canary_version"] = "2.0.0"
	rollout["canary_percent"] = 25
	routing := obj(obj(obj(v, "services"), "reports-service"), "instance_routing")
	routing["preempt"] = true
	routing["recovery_hold_down"] = "1m"
	identity := installation()
	identity.MinimumControlRevision = ^uint64(0)
	p, err := PlanSQLiteState(document(t, v), identity)
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Configs()
	if err != nil {
		t.Fatal(err)
	}
	if c.Registry.MaxPathsPerInstance != 8 || c.Registry.MaxTunnels != 20 || c.Control.MaxRegistrations != 20 || c.Registry.MaxVersions != 3 || c.Registry.MaxTunnelsPerService != 4 || !c.Registry.FrontendEnabled {
		t.Fatal("nondefault registry settings lost")
	}
	if c.Replay.Capacity != 1000 || c.Replay.CallerCapacity != 100 || c.Replay.AdmittedRPS != 3 || c.Replay.AdmittedBurst != 7 || c.MinimumControlRevision != ^uint64(0) {
		t.Fatal("nondefault replay/identity settings lost")
	}
	if s := c.Registry.Services["my-service"]; s.Rollout.Canary != "2.0.0" || s.Rollout.CanaryPercent != 25 {
		t.Fatal("canary lost")
	}
	if ap := c.Registry.Services["reports-service"].ActivePassive; !ap.Preempt || *ap.HoldDown != time.Minute {
		t.Fatal("preemption lost")
	}
}
