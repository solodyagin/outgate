package deployment

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/solodyagin/outgate-sdk/replay"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/gateway"
	"github.com/solodyagin/outgate/internal/registry"
)

// State, security, transport and shared resources come from the same YAML.
// Explicit installation evidence/reservations are supplied by this harness.
func TestSecurityBindingOpensRealSharedRuntime(t *testing.T) {
	_, v := fixture(t)
	caller := obj(obj(obj(v, "interservice"), "callers"), "my-service")
	recipient := obj(obj(obj(v, "interservice"), "recipients"), "reports-service")
	v["services"] = map[string]any{"api": map[string]any{"allowed_paths": []any{"/api"}, "rollout": map[string]any{"stable_version": "1.0.0"}, "grant_permissions": map[string]any{"allowed_path_modes": []any{"preserve"}}}}
	v["frontend_override"] = map[string]any{"enabled": false}
	access := obj(v, "interservice")
	access["callers"] = map[string]any{"api": caller}
	access["recipients"] = map[string]any{"api": recipient}
	access["policies"] = []any{map[string]any{"caller": "api", "target": "api", "paths": []any{"/api"}, "methods": []any{"GET"}, "allow_background": true, "allow_user_context": false}}
	obj(obj(v, "storage"), "control")["path"] = filepath.Join(t.TempDir(), "control.db")
	obj(obj(v, "storage"), "replay")["path"] = filepath.Join(t.TempDir(), "replay.db")
	doc := document(t, v)
	sources := load(t, doc)
	statePlan, err := PlanSQLiteState(doc, installation())
	if err != nil {
		t.Fatal(err)
	}
	components, err := statePlan.Configs()
	if err != nil {
		t.Fatal(err)
	}
	control := components.Control
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	check(controlstate.Initialize(t.Context(), control))
	store, err := controlstate.Open(t.Context(), control)
	check(err)
	routes := components.Registry
	reg, err := registry.New(routes)
	check(err)
	snapshot, err := reg.MarshalSnapshot()
	check(err)
	id, err := uuid.NewV7()
	check(err)
	_, err = store.CommitRegistry(t.Context(), controlstate.Change{OperationID: id.String(), Actor: "operator", ExpectedRevision: 1, Reason: "deployment sources integration"}, routes, snapshot, nil)
	check(err)
	check(store.Close())
	replayConfig := components.Replay
	check(replay.InitializeSQLite(t.Context(), replayConfig))
	transportPlan, err := PlanQUICTransport(doc, transportReservations())
	check(err)
	base, err := transportPlan.Bind(gateway.Config{})
	check(err)
	base, err = BindHTTPPolicy(doc, base)
	check(err)
	base, err = BindSharedResources(doc, base, 65536)
	check(err)
	base, err = statePlan.Bind(base)
	check(err)
	bound, err := sources.Bind(base)
	check(err)
	runtime, err := gateway.OpenSQLiteRuntime(t.Context(), bound)
	check(err)
	// Construction uses real, provisioned SQLite stores and exact key mappings.
	// No 120s replay warmup is skipped, and no signed business exchange is claimed.
	if runtime.Ready(t.Context()) == nil {
		t.Fatal("unstarted/warming runtime ready")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	check(runtime.Shutdown(ctx))
	if _, err := sources.Health(t.Context()); err != nil {
		t.Fatal("runtime closed borrowed sources", err)
	}
	check(sources.Close())
}
