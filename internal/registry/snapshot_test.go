package registry

import (
	"bytes"
	"encoding/json"
	"maps"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func snapshotRoundTrip(t *testing.T, r *Registry, cfg Config) *Registry {
	t.Helper()
	data, err := r.MarshalSnapshot()
	ok(t, err)
	restored, err := RestoreSnapshot(cfg, data)
	ok(t, err)
	again, err := restored.MarshalSnapshot()
	ok(t, err)
	if !bytes.Equal(data, again) {
		t.Fatal("recovery changed persisted state")
	}
	return restored
}

func TestSnapshotRetainsPolicyWithoutSessions(t *testing.T) {
	cfg := Config{FrontendService: "web", FrontendEnabled: true, Services: map[string]ServiceConfig{
		"api": serviceConfig("/api"), "web": serviceConfig("/"),
	}}
	r := model(t, cfg)
	stable := r.ready(mount(registration("api", "one", "v1", "/api"), "/api"), QUIC)
	r.activate("api", "/api")
	r.ready(mount(registration("api", "two", "v2", "/api"), "/api"), WSS)
	ok(t, r.UpdateRolloutAuthorized("api", Rollout{Stable: "v1", Canary: "v2", CanaryPercent: 40}, r.Revision()))
	ok(t, r.PromoteAuthorized("api", r.Revision()))
	r.ready(registration("web", "web-one", "v1", "/"), QUIC)
	r.activate("web", "/")
	wantMounts, wantRevision, err := r.Discovery("api")
	ok(t, err)
	// Startup YAML has old rollout and root settings. Recovery must use state.
	cfg.FrontendEnabled = false
	restored := snapshotRoundTrip(t, r.Registry, cfg)
	if len(restored.sessions) != 0 || restored.Revision() != r.Revision() {
		t.Fatal("restored live sessions or changed revision")
	}
	policy, _, err := restored.Rollout("api")
	ok(t, err)
	if policy.Stable != "v2" || policy.PreviousStable != "v1" {
		t.Fatalf("lost promotion: %+v", policy)
	}
	gotMounts, gotRevision, err := restored.Discovery("api")
	ok(t, err)
	if !maps.Equal(gotMounts, wantMounts) || gotRevision != wantRevision {
		t.Fatal("lost discovery or service revision")
	}
	for _, uri := range []string{"/api/work", "/dashboard"} {
		if d := restored.Lookup(uri, "", nil); d.Status != http.StatusServiceUnavailable || d.Upstream || d.Session != nil {
			t.Fatalf("route fell through after recovery: %+v", d)
		}
	}
	wantError(t, restored.SetReady(stable, true), ErrClosedSession)
	wantError(t, restored.Disconnect(stable), ErrClosedSession)
	reg := mount(registration("api", "one", "v2", "/api"), "/api")
	joined, err := restored.RegisterAuthorized(reg, QUIC)
	ok(t, err)
	if joined.Discovered || joined.Paths["/api"] != Active {
		t.Fatal("reconnect lost recovered version or ownership")
	}
	if d := restored.Lookup("/api/work", "", nil); d.Status != http.StatusServiceUnavailable {
		t.Fatal("fresh session became ready automatically")
	}
	ok(t, restored.SetReady(joined.Session, true))
	if d := restored.Lookup("/api/work", "", nil); d.Session != joined.Session {
		t.Fatalf("fresh ready session unavailable: %+v", d)
	}
	versions, err := restored.Versions("api")
	ok(t, err)
	if len(versions) != 2 || versions[0].Instances != 0 || versions[1].Instances != 1 {
		t.Fatalf("live counters restored incorrectly: %+v", versions)
	}
}

func TestSnapshotRetainsTombstonesAndSharedOwners(t *testing.T) {
	cfg := Config{SharedPaths: []string{"/shared"}, Services: map[string]ServiceConfig{
		"a": serviceConfig("/shared", "/retired", "/pending"), "b": serviceConfig("/shared"),
	}}
	r := model(t, cfg)
	a := r.ready(registration("a", "one", "v1", "/shared", "/retired", "/pending"), QUIC)
	r.ready(registration("b", "two", "v1", "/shared"), WSS)
	r.activate("a", "/shared")
	r.activate("b", "/shared")
	r.activate("a", "/retired")
	ok(t, r.RetireAuthorized("a", "/retired", r.Revision()))
	v := r.connect(registration("a", "old", "old", "/pending"), QUIC).Session
	ok(t, r.Disconnect(v))
	ok(t, r.RetireVersionAuthorized("a", "old", r.Revision(), true))
	restored := snapshotRoundTrip(t, r.Registry, cfg)
	for _, uri := range []string{"/shared", "/retired"} {
		if d := restored.Lookup(uri, "", nil); d.Status != http.StatusServiceUnavailable || d.Upstream {
			t.Fatalf("lost retained route: %+v", d)
		}
	}
	if d := restored.Lookup("/pending", "", nil); !d.Upstream {
		t.Fatal("pending path started routing")
	}
	_, err := restored.RegisterAuthorized(registration("a", "new", "v1", "/retired"), QUIC)
	wantError(t, err, ErrPathForbidden)
	_, err = restored.RegisterAuthorized(registration("a", "new", "old", "/pending"), QUIC)
	wantError(t, err, ErrInvalid)
	wantError(t, restored.SetReady(a, true), ErrClosedSession)
}

func TestSnapshotRetainsDevelopmentReleaseAndDisabledRoot(t *testing.T) {
	cfg := Config{Development: true, FrontendService: "web", FrontendEnabled: true,
		Services: map[string]ServiceConfig{"web": serviceConfig("/", "/released")}}
	r := model(t, cfg)
	r.ready(registration("web", "one", "v1", "/", "/released"), QUIC)
	ok(t, r.RetireAuthorized("web", "/released", r.Revision()))
	ok(t, r.ReleaseAuthorized("web", "/released", r.Revision(), true, true))
	ok(t, r.SetFrontendEnabledAuthorized(false, r.Revision()))
	restored := snapshotRoundTrip(t, r.Registry, cfg)
	if d := restored.Lookup("/", "", nil); !d.Upstream {
		t.Fatal("old YAML enabled root")
	}
	joined, err := restored.RegisterAuthorized(registration("web", "new", "v1", "/released"), WSS)
	ok(t, err)
	if joined.Paths["/released"] != Pending {
		t.Fatal("released development route reactivated")
	}
}

func TestSnapshotRejectsMalformedAndIncompatibleState(t *testing.T) {
	cfg := Config{Services: map[string]ServiceConfig{"api": serviceConfig("/api")}}
	r := model(t, cfg)
	r.ready(mount(registration("api", "one", "v1", "/api"), "/api"), QUIC)
	r.activate("api", "/api")
	data, err := r.MarshalSnapshot()
	ok(t, err)
	for name, corrupt := range map[string][]byte{
		"empty": nil, "oversized": bytes.Repeat([]byte{' '}, MaxSnapshotBytes+1),
		"truncated": data[:len(data)-2], "trailing": append(bytes.Clone(data), []byte("{}")...),
		"unknown":   bytes.Replace(data, []byte(`"format":1`), []byte(`"unknown":1,"format":1`), 1),
		"duplicate": bytes.Replace(data, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1),
		"format":    bytes.Replace(data, []byte(`"format":1`), []byte(`"format":2`), 1),
		"revision":  bytes.Replace(data, []byte(`"revision":"2"`), []byte(`"revision":"02"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := RestoreSnapshot(cfg, corrupt)
			wantError(t, err, ErrSnapshot)
			if got != nil {
				t.Fatal("published invalid snapshot")
			}
		})
	}
	mutations := map[string]func(*registrySnapshot){
		"future-service-revision": func(s *registrySnapshot) {
			v := s.Services["api"]
			v.RouteRevision = math.MaxUint64
			s.Services["api"] = v
		},
		"missing-service":     func(s *registrySnapshot) { delete(s.Services, "api") },
		"unknown-owner":       func(s *registrySnapshot) { s.Routes["/api"]["other"] = Active },
		"bad-state":           func(s *registrySnapshot) { s.Routes["/api"]["api"] = "ready" },
		"non-normalized":      func(s *registrySnapshot) { s.Routes["/api/"] = s.Routes["/api"]; delete(s.Routes, "/api") },
		"uncovered-route":     func(s *registrySnapshot) { s.Routes["/api/new"] = map[string]RouteState{"api": Active} },
		"mount-without-owner": func(s *registrySnapshot) { delete(s.Routes, "/api") },
		"retired-stable": func(s *registrySnapshot) {
			v := s.Services["api"].Versions["v1"]
			v.Retired = true
			s.Services["api"].Versions["v1"] = v
		},
		"invalid-transport": func(s *registrySnapshot) {
			v := s.Services["api"].Versions["v1"]
			v.Transports = []Transport{"tcp"}
			s.Services["api"].Versions["v1"] = v
		},
		"bad-mount":          func(s *registrySnapshot) { s.Services["api"].Versions["v1"].Mounts["!bad"] = "/api" },
		"production-release": func(s *registrySnapshot) { s.Released = []string{"/api/old"} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var state registrySnapshot
			ok(t, json.Unmarshal(data, &state))
			mutate(&state)
			corrupt, err := encodeSnapshot(state)
			ok(t, err)
			got, err := RestoreSnapshot(cfg, corrupt)
			wantError(t, err, ErrSnapshot)
			if got != nil {
				t.Fatal("published invalid snapshot")
			}
		})
	}
	for name, change := range map[string]func(*Config){
		"development": func(c *Config) { c.Development = true },
		"shared":      func(c *Config) { c.SharedPaths = []string{"/api"} },
		"reserved":    func(c *Config) { c.ReservedAPIPrefixes = []string{"/private"} },
		"allowlist":   func(c *Config) { c.Services = map[string]ServiceConfig{"api": serviceConfig("/other")} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cfg
			change(&changed)
			_, err := RestoreSnapshot(changed, data)
			wantError(t, err, ErrSnapshot)
		})
	}
}

func TestSnapshotEmptyAndUint64Revision(t *testing.T) {
	cfg := Config{Services: map[string]ServiceConfig{"api": serviceConfig("/api")}}
	r := model(t, cfg)
	snapshotRoundTrip(t, r.Registry, cfg)
	r.revision = math.MaxUint64
	snapshotRoundTrip(t, r.Registry, cfg)
	_, err := r.RegisterAuthorized(registration("api", "one", "v1", "/api"), QUIC)
	wantError(t, err, ErrQuota)
	// Size limits apply to encoding as well as untrusted recovery input.
	var state registrySnapshot
	state.Policy.Frontend = strings.Repeat("x", MaxSnapshotBytes)
	_, err = encodeSnapshot(state)
	wantError(t, err, ErrSnapshot)
}

func TestSnapshotPreservesPartialMountDiscovery(t *testing.T) {
	cfg := Config{Services: map[string]ServiceConfig{"api": serviceConfig("/api")}}
	r := model(t, cfg)
	r.ready(registration("api", "one", "v1", "/api"), QUIC)
	r.ready(registration("api", "two", "v2", "/api"), QUIC)
	r.activate("api", "/api")
	ok(t, r.UpdateRolloutAuthorized("api", Rollout{Stable: "v1", Canary: "v2", CanaryPercent: 50}, r.Revision()))
	// An additional replica may discover a mount that v2 has not declared.
	r.connect(mount(registration("api", "three", "v1", "/api"), "/api"), QUIC)
	restored := snapshotRoundTrip(t, r.Registry, cfg)
	mounts, _, err := restored.Discovery("api")
	ok(t, err)
	if len(mounts) != 0 {
		t.Fatal("published a mount absent from canary")
	}
}

func TestSnapshotActivePassiveNeedsFreshReadiness(t *testing.T) {
	service := serviceConfig("/api")
	service.ActivePassive = &ActivePassive{Orders: map[string][]string{"v1": {"one", "two"}}}
	cfg := Config{Services: map[string]ServiceConfig{"api": service}}
	r := model(t, cfg)
	r.ready(registration("api", "one", "v1", "/api"), QUIC)
	r.ready(registration("api", "two", "v1", "/api"), WSS)
	r.activate("api", "/api")
	ok(t, r.SwitchPrimaryAuthorized("api", "v1", "two", r.Revision()))
	restored := snapshotRoundTrip(t, r.Registry, cfg)
	if restored.services["api"].versions["v1"].primary != nil {
		t.Fatal("restored a live primary handle")
	}
	reg := registration("api", "two", "v1", "/api")
	joined, err := restored.RegisterAuthorized(reg, WSS)
	ok(t, err)
	if d := restored.Lookup("/api", "", nil); d.Status != http.StatusServiceUnavailable {
		t.Fatal("restored readiness")
	}
	ok(t, restored.SetReady(joined.Session, true))
	if d := restored.Lookup("/api", "", nil); d.Session != joined.Session {
		t.Fatal("fresh standby unavailable")
	}
	changed := cfg
	changed.Services = map[string]ServiceConfig{"api": serviceConfig("/api")}
	data, err := r.MarshalSnapshot()
	ok(t, err)
	_, err = RestoreSnapshot(changed, data)
	wantError(t, err, ErrSnapshot)
}

func TestSnapshotConcurrentRuntimeChanges(t *testing.T) {
	cfg := Config{Services: map[string]ServiceConfig{"api": serviceConfig("/api")}}
	r := model(t, cfg)
	session := r.ready(registration("api", "one", "v1", "/api"), QUIC)
	r.activate("api", "/api")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if err := r.SetReady(session, i%2 == 0); err != nil {
				t.Error(err)
				return
			}
			r.Lookup("/api", "", nil)
		}
	}()
	for i := 0; i < 50; i++ {
		snapshotRoundTrip(t, r.Registry, cfg)
	}
	wg.Wait()
}

func FuzzRestoreSnapshot(f *testing.F) {
	cfg := Config{Services: map[string]ServiceConfig{"api": serviceConfig("/api")}}
	r, err := New(cfg)
	if err != nil {
		f.Fatal(err)
	}
	data, err := r.MarshalSnapshot()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`{"format":1}`))
	f.Fuzz(func(t *testing.T, candidate []byte) {
		restored, err := RestoreSnapshot(cfg, candidate)
		if err != nil {
			if restored != nil {
				t.Fatal("returned state after failed recovery")
			}
			return
		}
		again, err := restored.MarshalSnapshot()
		ok(t, err)
		if !bytes.Equal(candidate, again) {
			t.Fatal("recovery accepted noncanonical state")
		}
	})
}
