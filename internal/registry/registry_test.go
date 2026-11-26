package registry

import (
	"errors"
	"maps"
	"net/http"
	"sync"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

func serviceConfig(paths ...string) ServiceConfig {
	return ServiceConfig{AllowedPaths: paths, Rollout: Rollout{Stable: "v1"}}
}

func registration(service, instance, version string, paths ...string) v1.Register {
	return v1.Register{
		Type: "register", ProtocolVersion: 1, ServiceID: service, InstanceID: instance, Version: version,
		Paths: paths, PathMode: "preserve", MaxConcurrentRequests: 100,
		Capabilities: v1.BaselineCapabilities(), RequiredCapabilities: v1.BaselineCapabilities(),
		ReadinessCheckConfigured: true,
	}
}

func mount(reg v1.Register, path string) v1.Register {
	reg.Mounts = map[string]string{"api": path}
	reg.Capabilities = append(reg.Capabilities, "mount_discovery")
	reg.RequiredCapabilities = append(reg.RequiredCapabilities, "mount_discovery")
	return reg
}

type testRegistry struct {
	*Registry
	t     *testing.T
	clock time.Time
	draw  int
}

func model(t *testing.T, cfg Config) *testRegistry {
	t.Helper()
	test := &testRegistry{t: t, clock: time.Unix(1000, 0)}
	r, err := newRegistry(cfg, func() time.Time { return test.clock }, func(int) int { return test.draw })
	ok(t, err)
	test.Registry = r
	return test
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantError(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got error %v, want %v", err, want)
	}
}

func (r *testRegistry) connect(reg v1.Register, transport Transport) Registration {
	r.t.Helper()
	result, err := r.RegisterAuthorized(reg, transport)
	ok(r.t, err)
	return result
}

func (r *testRegistry) ready(reg v1.Register, transport Transport) *Session {
	r.t.Helper()
	session := r.connect(reg, transport).Session
	ok(r.t, r.SetReady(session, true))
	return session
}

func (r *testRegistry) activate(service, path string) {
	r.t.Helper()
	ok(r.t, r.ActivateAuthorized(service, path, r.Revision()))
}

func (r *testRegistry) selected(raw, target string, want *Session) {
	r.t.Helper()
	got := r.Lookup(raw, target, nil)
	if got.Session != want || want == nil || got.Status != 0 || got.Upstream {
		r.t.Fatalf("%s: got %+v, want session %+v", raw, got, want)
	}
}

func (r *testRegistry) status(raw, target string, status int) Decision {
	r.t.Helper()
	got := r.Lookup(raw, target, nil)
	if got.Status != status || got.Session != nil || got.Upstream ||
		status == http.StatusServiceUnavailable && got.RetryAfterSeconds != 1 {
		r.t.Fatalf("%s: got %+v, want status %d", raw, got, status)
	}
	return got
}

func TestAtomicRegistrationAndRetainedOwnership(t *testing.T) {
	r := model(t, Config{Services: map[string]ServiceConfig{"owner": serviceConfig("/api"), "other": serviceConfig("/api")}})
	reg := registration("owner", "one", "v1", "/api/orders/")
	start := r.connect(reg, QUIC)
	if !start.Discovered || !maps.Equal(start.Paths, map[string]RouteState{"/api/orders": Pending}) {
		t.Fatalf("unexpected registration: %+v", start)
	}
	r.status("/api/orders", "", http.StatusNotFound)
	r.status("/api/orders", "owner", http.StatusServiceUnavailable)
	r.status("/api/orders", "unknown", http.StatusForbidden)
	wantError(t, r.ActivateAuthorized("owner", "/api/orders", r.Revision()), ErrConflict)
	ok(t, r.SetReady(start.Session, true))
	r.activate("owner", "/api/orders")
	r.selected("/api/orders/%D1%8F?keep=%2f&v=1", "", start.Session)
	r.selected("/api/orders/a%252fb", "", start.Session)
	for _, path := range []string{"/api/orders/%2Fescape", "/api/orders/%5cescape", "/api/orders/%2e%2e", "/api/orders//x", "/%ff", "/%"} {
		r.status(path, "", http.StatusBadRequest)
	}
	r.status("/api/ordersx", "", http.StatusNotFound)
	if !r.Lookup("/apix", "", nil).Upstream {
		t.Fatal("prefix comparison ignored segment boundary")
	}

	initial := r.Revision()
	_, err := r.RegisterAuthorized(registration("other", "two", "v2", "/api/free", "/api/orders"), WSS)
	wantError(t, err, ErrPathConflict)
	_, err = r.RegisterAuthorized(registration("other", "two", "v2", "/api/free", "/private"), WSS)
	wantError(t, err, ErrPathForbidden)
	_, err = r.RegisterAuthorized(registration("other", "one", "v2", "/api/free"), WSS)
	wantError(t, err, ErrDuplicate)
	versions, err := r.Versions("other")
	ok(t, err)
	if len(versions) != 0 || r.Revision() != initial {
		t.Fatal("failed registration leaked state")
	}
	free := r.ready(registration("owner", "two", "v1", "/api/free"), WSS)
	r.activate("owner", "/api/free")
	r.selected("/api/free", "", free)

	ok(t, r.Drain(start.Session))
	_, err = r.RegisterAuthorized(reg, WSS)
	wantError(t, err, ErrDuplicate)
	r.status("/api/orders", "", http.StatusServiceUnavailable)
	ok(t, r.Disconnect(start.Session))
	r.clock = r.clock.Add(10 * time.Second)
	reconnect := r.connect(reg, WSS)
	if reconnect.Discovered || reconnect.Paths["/api/orders"] != Active || reconnect.RouteRevision <= start.RouteRevision {
		t.Fatalf("reconnect lost ownership: %+v", reconnect)
	}
	wantError(t, r.Disconnect(start.Session), ErrClosedSession)
	r.status("/api/orders", "", http.StatusServiceUnavailable)
	ok(t, r.SetReady(reconnect.Session, true))
	r.selected("/api/orders", "", reconnect.Session)
	versions, err = r.Versions("owner")
	ok(t, err)
	if len(versions) != 1 || !versions[0].FirstSeen.Equal(time.Unix(1000, 0)) ||
		!versions[0].LastSeen.Equal(r.clock) || len(versions[0].Transports) != 2 {
		t.Fatalf("unexpected version history: %+v", versions)
	}
}

func TestLongestSharedRetiredAndReleased(t *testing.T) {
	r := model(t, Config{SharedPaths: []string{"/api/shared"},
		Services: map[string]ServiceConfig{"a": serviceConfig("/api"), "b": serviceConfig("/api")}})
	parent := r.ready(registration("a", "a-parent", "v1", "/api"), QUIC)
	r.activate("a", "/api")
	a := r.ready(registration("a", "a-shared", "v1", "/api/shared"), WSS)
	b := r.ready(registration("b", "b-shared", "v1", "/api/shared", "/api/shared/nested"), QUIC)
	r.selected("/api/shared", "", parent)
	r.activate("a", "/api/shared")
	r.activate("b", "/api/shared")
	r.selected("/api/shared", "", a)
	r.selected("/api/shared", "", b)
	r.selected("/api/shared", "b", b)

	r.activate("b", "/api/shared/nested")
	r.status("/api/shared/nested/item", "a", http.StatusForbidden)
	stale := r.Revision()
	ok(t, r.RetireAuthorized("a", "/api/shared", stale))
	wantError(t, r.RetireAuthorized("b", "/api/shared", stale), ErrRevisionConflict)
	r.selected("/api/shared", "", b)
	r.status("/api/shared", "a", http.StatusServiceUnavailable)
	ok(t, r.RetireAuthorized("b", "/api/shared", r.Revision()))
	r.status("/api/shared", "", http.StatusServiceUnavailable)
	_, err := r.RegisterAuthorized(registration("a", "back", "v1", "/api/shared"), QUIC)
	wantError(t, err, ErrPathForbidden)
	wantError(t, r.ReleaseAuthorized("a", "/api/shared", r.Revision(), false, true), ErrConflict)
	wantError(t, r.ReleaseAuthorized("a", "/api/shared", r.Revision(), true, false), ErrConflict)
	ok(t, r.ReleaseAuthorized("a", "/api/shared", r.Revision(), true, true))
	r.status("/api/shared", "", http.StatusServiceUnavailable)
	ok(t, r.ReleaseAuthorized("b", "/api/shared", r.Revision(), true, true))
	r.selected("/api/shared", "", parent)
	r.selected("/api/shared/nested/item", "", b)

	next := r.ready(registration("a", "back", "v1", "/api/shared"), QUIC)
	r.activate("a", "/api/shared")
	r.selected("/api/shared", "", next)
	r.selected("/api/shared", "", next)
}

func TestRootBeforeAndAfterExplicitActivation(t *testing.T) {
	for _, development := range []bool{false, true} {
		r := model(t, Config{Development: development, FrontendService: "spa", FrontendEnabled: true,
			ReservedAPIPrefixes: []string{"/backend"}, Services: map[string]ServiceConfig{
				"spa": serviceConfig("/"), "api": serviceConfig("/api"),
			}})
		if !r.Lookup("/", "", nil).Upstream {
			t.Fatal("override activated before registration")
		}
		_, err := r.RegisterAuthorized(registration("spa", "bad", "v1", "/elsewhere"), QUIC)
		wantError(t, err, ErrPathForbidden)
		_, err = r.RegisterAuthorized(registration("api", "bad", "v1", "/"), QUIC)
		wantError(t, err, ErrPathForbidden)
		root := r.ready(registration("spa", "frontend", "v1", "/"), WSS)
		if !development {
			if !r.Lookup("/page", "", nil).Upstream {
				t.Fatal("pending override replaced upstream")
			}
			r.activate("spa", "/")
		}
		r.status("/api/missing", "", http.StatusNotFound)
		r.status("/backend/missing", "", http.StatusNotFound)
		r.selected("/apix", "", root)
		ok(t, r.Disconnect(root))
		r.status("/users", "", http.StatusServiceUnavailable)
		wantError(t, r.RetireAuthorized("spa", "/", r.Revision()), ErrInvalid)
		ok(t, r.SetFrontendEnabledAuthorized(false, r.Revision()))
		if !r.Lookup("/users", "", nil).Upstream {
			t.Fatal("disabled override did not restore upstream")
		}
	}
}

func TestRolloutCoverageAndNoRedistribution(t *testing.T) {
	r := model(t, Config{Services: map[string]ServiceConfig{"reports": serviceConfig("/api")}})
	stable := r.ready(mount(registration("reports", "stable", "v1", "/api", "/api/reports"), "/api"), QUIC)
	r.activate("reports", "/api")
	r.activate("reports", "/api/reports")
	r.ready(mount(registration("reports", "canary", "v2", "/api"), "/api"), WSS)
	policy := Rollout{Stable: "v1", Canary: "v2", CanaryPercent: 20}
	wantError(t, r.UpdateRolloutAuthorized("reports", policy, r.Revision()), ErrConflict)
	canary := r.ready(registration("reports", "canary-reports", "v2", "/api/reports"), WSS)
	_, routeRevision, err := r.Discovery("reports")
	ok(t, err)
	ok(t, r.UpdateRolloutAuthorized("reports", policy, r.Revision()))
	currentMounts, currentRevision, err := r.Discovery("reports")
	ok(t, err)
	if currentRevision != routeRevision || currentMounts["api"].Prefix != "/api" {
		t.Fatal("unchanged mount changed route revision")
	}
	r.draw = 0
	r.selected("/api/reports", "", canary)
	r.draw = 99
	r.selected("/api/reports", "", stable)
	ok(t, r.Disconnect(canary))
	r.draw = 0
	decision := r.status("/api/reports", "", http.StatusServiceUnavailable)
	if decision.Version != "v2" {
		t.Fatalf("canary selection changed after failure: %+v", decision)
	}
	policy.CanaryPercent = 0
	ok(t, r.UpdateRolloutAuthorized("reports", policy, r.Revision()))
	r.selected("/api/reports", "", stable)
	wantError(t, r.PromoteAuthorized("reports", r.Revision()), ErrConflict)
	r.ready(registration("reports", "canary-reports", "v2", "/api/reports"), QUIC)
	ok(t, r.PromoteAuthorized("reports", r.Revision()))
	got, _, err := r.Rollout("reports")
	ok(t, err)
	if got != (Rollout{Stable: "v2", PreviousStable: "v1"}) {
		t.Fatalf("unexpected promotion: %+v", got)
	}
	ok(t, r.RollbackAuthorized("reports", r.Revision()))
	r.selected("/api/reports", "", stable)
}

func TestCandidateMountAndRouteRevision(t *testing.T) {
	r := model(t, Config{Development: true, Services: map[string]ServiceConfig{"reports": serviceConfig("/api")}})
	stable := r.ready(mount(registration("reports", "stable", "v1", "/api"), "/api"), QUIC)
	_, rev, err := r.Discovery("reports")
	ok(t, err)
	r.ready(mount(registration("reports", "candidate", "v2", "/api", "/api/new"), "/api/new"), WSS)
	r.selected("/api/new", "", stable)
	if got := r.Lookup("/api", "reports", &rev); got.Status != http.StatusConflict {
		t.Fatalf("stale route revision accepted: %+v", got)
	}
	wantError(t, r.UpdateRolloutAuthorized("reports", Rollout{Stable: "v1", Canary: "v2", CanaryPercent: 20}, r.Revision()), ErrConflict)
}

func TestActivePassiveSwitchDrainAndPreemption(t *testing.T) {
	for _, preempt := range []bool{false, true} {
		cfg := serviceConfig("/api")
		cfg.ActivePassive = &ActivePassive{Orders: map[string][]string{"v1": {"main", "backup"}}, Preempt: preempt}
		r := model(t, Config{Services: map[string]ServiceConfig{"reports": cfg}})
		bad := registration("reports", "main", "v1", "/api")
		bad.ReadinessCheckConfigured = false
		_, err := r.RegisterAuthorized(bad, QUIC)
		wantError(t, err, ErrInvalid)
		primary := r.ready(registration("reports", "main", "v1", "/api"), QUIC)
		_, err = r.RegisterAuthorized(registration("reports", "backup", "v1", "/api/narrow"), WSS)
		wantError(t, err, ErrInvalid)
		backup := r.ready(registration("reports", "backup", "v1", "/api"), WSS)
		r.activate("reports", "/api")
		r.selected("/api", "", primary)
		ok(t, r.SetReady(primary, false))
		r.selected("/api", "", backup)
		ok(t, r.SetReady(primary, true))
		r.clock = r.clock.Add(29 * time.Second)
		r.selected("/api", "", backup)
		ok(t, r.SetReady(primary, false))
		ok(t, r.SetReady(primary, true))
		r.clock = r.clock.Add(29 * time.Second)
		r.selected("/api", "", backup)
		r.clock = r.clock.Add(time.Second)
		if preempt {
			r.selected("/api", "", primary)
		} else {
			r.selected("/api", "", backup)
		}
		ok(t, r.SwitchPrimaryAuthorized("reports", "v1", "main", r.Revision()))
		r.selected("/api", "", primary)
		ok(t, r.Drain(primary))
		r.selected("/api", "", backup)
		wantError(t, r.SetReady(primary, true), ErrConflict)
	}
}

func TestVersionRetireRestoreAndQuota(t *testing.T) {
	r := model(t, Config{MaxVersions: 2, Services: map[string]ServiceConfig{"reports": serviceConfig("/api")}})
	r.ready(registration("reports", "stable", "v1", "/api"), QUIC)
	candidate := r.ready(registration("reports", "candidate", "v2", "/api"), WSS)
	wantError(t, r.RetireVersionAuthorized("reports", "v2", r.Revision(), true), ErrConflict)
	ok(t, r.Disconnect(candidate))
	ok(t, r.RetireVersionAuthorized("reports", "v2", r.Revision(), true))
	_, err := r.RegisterAuthorized(registration("reports", "candidate", "v2", "/api"), WSS)
	wantError(t, err, ErrInvalid)
	v3 := r.ready(registration("reports", "new", "v3", "/api"), QUIC)
	wantError(t, r.RestoreVersionAuthorized("reports", "v2", r.Revision()), ErrQuota)
	ok(t, r.Disconnect(v3))
	ok(t, r.RetireVersionAuthorized("reports", "v3", r.Revision(), true))
	ok(t, r.RestoreVersionAuthorized("reports", "v2", r.Revision()))
	r.ready(registration("reports", "candidate", "v2", "/api"), WSS)
}

func TestConcurrentRegistrationAndRolloutRevision(t *testing.T) {
	r := model(t, Config{Development: true, Services: map[string]ServiceConfig{"reports": serviceConfig("/api")}})
	var group sync.WaitGroup
	results := make(chan error, 16)
	reg := registration("reports", "same", "v1", "/api")
	for range cap(results) {
		group.Go(func() {
			result, err := r.RegisterAuthorized(reg, QUIC)
			if err == nil {
				err = r.SetReady(result.Session, true)
			}
			results <- err
		})
	}
	group.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else {
			wantError(t, err, ErrDuplicate)
		}
	}
	if winners != 1 {
		t.Fatalf("got %d registration winners", winners)
	}
	revision := r.Revision()
	changes := make(chan error, 2)
	for range cap(changes) {
		group.Go(func() { changes <- r.UpdateRolloutAuthorized("reports", Rollout{Stable: "v1"}, revision) })
	}
	group.Wait()
	close(changes)
	winners = 0
	for err := range changes {
		if err == nil {
			winners++
		} else {
			wantError(t, err, ErrRevisionConflict)
		}
	}
	if winners != 1 {
		t.Fatalf("got %d concurrent rollout commits", winners)
	}
}

func TestWeightedActivationRequiresCoverageAndMountAgreement(t *testing.T) {
	cfg := serviceConfig("/api")
	cfg.Rollout = Rollout{Stable: "v1", Canary: "v2", CanaryPercent: 20}
	r := model(t, Config{Services: map[string]ServiceConfig{"svc": cfg}})
	r.ready(mount(registration("svc", "a", "v1", "/api", "/api/new"), "/api/new"), QUIC)
	r.ready(registration("svc", "b", "v2", "/api"), WSS)
	r.activate("svc", "/api")
	wantError(t, r.ActivateAuthorized("svc", "/api/new", r.Revision()), ErrConflict)

	alternate := mount(registration("svc", "b-new", "v2", "/api/new"), "/api/new")
	alternate.PathMode = "strip"
	_, err := r.RegisterAuthorized(alternate, WSS)
	wantError(t, err, ErrInvalid)

	// A second version may use a different path mode. It cannot publish the
	// same logical mount under a different mode when both versions have weight.
	alternate = mount(registration("svc", "b-alt", "v2", "/api/new"), "/api/new")
	r.ready(alternate, WSS)
	r.activate("svc", "/api/new")
	_, revision, err := r.Discovery("svc")
	ok(t, err)
	ok(t, r.RetireAuthorized("svc", "/api/new", r.Revision()))
	if got := r.Lookup("/api/new", "svc", &revision); got.Status != http.StatusConflict {
		t.Fatalf("retired mount did not invalidate revision: %+v", got)
	}

	r = model(t, Config{Services: map[string]ServiceConfig{"svc": serviceConfig("/api")}})
	r.ready(mount(registration("svc", "a", "v1", "/api"), "/api"), QUIC)
	r.activate("svc", "/api")
	alternate = mount(registration("svc", "b", "v2", "/api"), "/api")
	alternate.PathMode = "strip"
	r.ready(alternate, WSS)
	wantError(t, r.UpdateRolloutAuthorized("svc", cfg.Rollout, r.Revision()), ErrConflict)
}
