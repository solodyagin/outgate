package deployment

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/solodyagin/outgate-sdk/httpsig"
	"github.com/solodyagin/outgate-sdk/replay"
	"github.com/solodyagin/outgate/internal/config"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/gateway"
	"github.com/solodyagin/outgate/internal/registry"
)

// StateIdentity is trusted, independently provisioned installation evidence.
// Planning never generates epochs or guesses a durable control revision floor.
type StateIdentity struct {
	ControlEpoch, ReplayEpoch [32]byte
	MinimumControlRevision    uint64
}

type stateStoreInput struct {
	Driver, Path, Synchronous string
	Journal                   string `json:"journal_mode"`
	Namespace                 string
	Barrier                   string `json:"recovery_barrier"`
}
type readinessInput struct {
	Interval, Timeout string
	Status            string `json:"status_timeout"`
	Healthy           int    `json:"healthy_threshold"`
	Unhealthy         int    `json:"unhealthy_threshold"`
}
type routingInput struct {
	Strategy  string
	Preempt   *bool
	HoldDown  *string `json:"recovery_hold_down"`
	Readiness *readinessInput
	Versions  map[string]struct {
		Order []string `json:"instance_order"`
	}
}
type stateInput struct {
	Storage  struct{ Control, Replay stateStoreInput }
	Services map[string]struct {
		Paths   []string `json:"allowed_paths"`
		Rollout struct {
			Stable  string `json:"stable_version"`
			Canary  string `json:"canary_version"`
			Percent int    `json:"canary_percent"`
		}
		Routing routingInput `json:"instance_routing"`
	}
	Frontend struct {
		Enabled bool
		Service string `json:"service_id"`
	} `json:"frontend_override"`
	Routing struct {
		Strategy string
		Reserved []string `json:"reserved_api_prefixes"`
	}
	Tunnel struct {
		MaxPaths    int      `json:"max_paths_per_instance"`
		MaxTunnels  int      `json:"max_tunnels"`
		MaxVersions int      `json:"max_versions_per_service"`
		Shared      []string `json:"shared_paths"`
	}
	Security struct {
		Resources struct {
			PerService int `json:"tunnels_per_service"`
		} `json:"resource_limits"`
		Rates struct {
			RPS   int64 `json:"signed_per_second"`
			Burst int64 `json:"signed_burst"`
		} `json:"rate_limits"`
	}
	Interservice struct {
		Capacity       int64 `json:"replay_cache_max_entries"`
		CallerCapacity int64 `json:"replay_max_entries_per_caller"`
	}
}

// SQLiteStatePlan maps only registry and SQLite settings. It performs no IO,
// bootstrap, migration, import or rollback recovery and is not a launch plan.
type SQLiteStatePlan struct{ state StateConfigs }

func (*SQLiteStatePlan) String() string     { return "outgate SQLite state plan (redacted)" }
func (p *SQLiteStatePlan) GoString() string { return p.String() }

// StateConfigs are detached component inputs. They may be used by an explicitly
// authorized provisioning operation; constructing a plan does not perform one.
type StateConfigs struct {
	Control                controlstate.Config
	Registry               registry.Config
	Replay                 replay.SQLiteConfig
	MinimumControlRevision uint64
}

func (StateConfigs) String() string     { return "outgate SQLite component configuration (redacted)" }
func (c StateConfigs) GoString() string { return c.String() }

func PlanSQLiteState(doc *config.Document, identity StateIdentity) (*SQLiteStatePlan, error) {
	if doc == nil || doc.Mode() != "production" || identity.ControlEpoch == [32]byte{} || identity.ReplayEpoch == [32]byte{} || identity.ControlEpoch == identity.ReplayEpoch || identity.MinimumControlRevision == 0 {
		return nil, ErrProfile
	}
	var in stateInput
	in.Routing.Strategy = "round_robin"
	in.Routing.Reserved = []string{"/api"}
	in.Tunnel.MaxPaths = 32
	in.Tunnel.MaxTunnels = 1000
	in.Tunnel.MaxVersions = 100
	in.Security.Resources.PerService = 16
	in.Security.Rates.RPS = 1000
	in.Security.Rates.Burst = 2000
	in.Interservice.Capacity = 200000
	in.Interservice.CallerCapacity = 20000
	data, err := json.Marshal(doc.Values())
	if err != nil {
		return nil, ErrProfile
	}
	defer clear(data)
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, ErrProfile
	}
	for _, store := range []stateStoreInput{in.Storage.Control, in.Storage.Replay} {
		if store.Driver != "sqlite" || store.Journal != "WAL" || store.Synchronous != "FULL" || !localAbsolutePath(store.Path) {
			return nil, ErrProfile
		}
	}
	controlPath, replayPath := filepath.Clean(in.Storage.Control.Path), filepath.Clean(in.Storage.Replay.Path)
	if !separateDatabasePaths(controlPath, replayPath) {
		return nil, ErrProfile
	}
	barrier := in.Storage.Replay.Barrier
	if barrier == "" {
		barrier = "120s"
	}
	if d, err := time.ParseDuration(barrier); err != nil || d != replay.RecoveryBarrier {
		return nil, ErrProfile
	}
	if in.Tunnel.MaxTunnels < 1 || in.Tunnel.MaxTunnels > 1000000 || len(in.Services) == 0 || !httpsig.ValidReplayNamespace(in.Storage.Replay.Namespace) {
		return nil, ErrProfile
	}
	state := StateConfigs{
		Control:                controlstate.Config{Path: controlPath, Epoch: identity.ControlEpoch, RootFrontend: in.Frontend.Service, MaxRegistrations: in.Tunnel.MaxTunnels, Services: map[string][]string{}},
		Registry:               registry.Config{Services: map[string]registry.ServiceConfig{}, FrontendService: in.Frontend.Service, FrontendEnabled: in.Frontend.Enabled, ReservedAPIPrefixes: in.Routing.Reserved, SharedPaths: in.Tunnel.Shared, MaxPathsPerInstance: in.Tunnel.MaxPaths, MaxTunnels: in.Tunnel.MaxTunnels, MaxVersions: in.Tunnel.MaxVersions, MaxTunnelsPerService: in.Security.Resources.PerService},
		Replay:                 replay.SQLiteConfig{Path: replayPath, Namespace: in.Storage.Replay.Namespace, Epoch: identity.ReplayEpoch, Capacity: in.Interservice.Capacity, CallerCapacity: in.Interservice.CallerCapacity, AdmittedRPS: in.Security.Rates.RPS, AdmittedBurst: in.Security.Rates.Burst},
		MinimumControlRevision: identity.MinimumControlRevision,
	}
	for id, service := range in.Services {
		cfg := registry.ServiceConfig{AllowedPaths: service.Paths, Rollout: registry.Rollout{Stable: service.Rollout.Stable, Canary: service.Rollout.Canary, CanaryPercent: service.Rollout.Percent}}
		routing := service.Routing
		strategy := routing.Strategy
		if strategy == "" {
			strategy = in.Routing.Strategy
		}
		if strategy == "active_passive" {
			if !defaultReadiness(routing.Readiness) {
				return nil, ErrProfile
			}
			hold := 30 * time.Second
			if routing.HoldDown != nil {
				d, err := time.ParseDuration(*routing.HoldDown)
				if err != nil {
					return nil, ErrProfile
				}
				hold = d
			}
			cfg.ActivePassive = &registry.ActivePassive{Orders: map[string][]string{}, HoldDown: &hold}
			if routing.Preempt != nil {
				cfg.ActivePassive.Preempt = *routing.Preempt
			}
			for version, pool := range routing.Versions {
				cfg.ActivePassive.Orders[version] = pool.Order
			}
		} else if strategy != "round_robin" || routing.Preempt != nil || routing.HoldDown != nil || routing.Readiness != nil || routing.Versions != nil {
			return nil, ErrProfile
		}
		state.Registry.Services[id] = cfg
		state.Control.Services[id] = slices.Clone(service.Paths)
	}
	// Exercise the actual registry boundary instead of assuming schema validation
	// proves runtime compatibility. This does not open state or create routes.
	routes, err := registry.New(state.Registry)
	if err != nil {
		return nil, ErrProfile
	}
	if _, err := routes.MarshalSnapshot(); err != nil {
		return nil, ErrProfile
	}
	r := state.Replay
	if r.AdmittedRPS <= 0 || r.AdmittedBurst < 0 || r.Capacity < r.AdmittedBurst || r.AdmittedRPS > (r.Capacity-r.AdmittedBurst)/150 || r.CallerCapacity <= 0 || r.CallerCapacity >= r.Capacity {
		return nil, ErrProfile
	}
	return &SQLiteStatePlan{state: state}, nil
}
func defaultReadiness(r *readinessInput) bool {
	if r == nil {
		return true
	}
	for _, item := range []struct {
		value string
		want  time.Duration
	}{{r.Interval, 5 * time.Second}, {r.Timeout, 2 * time.Second}, {r.Status, 15 * time.Second}} {
		if item.value != "" {
			d, err := time.ParseDuration(item.value)
			if err != nil || d != item.want {
				return false
			}
		}
	}
	return (r.Healthy == 0 || r.Healthy == 2) && (r.Unhealthy == 0 || r.Unhealthy == 3)
}
func localAbsolutePath(path string) bool {
	return filepath.IsAbs(path) && !strings.HasPrefix(filepath.ToSlash(path), "//") && !strings.HasPrefix(path, `\\`) && !strings.ContainsRune(path, 0)
}
func separateDatabasePaths(a, b string) bool {
	if runtime.GOOS == "windows" {
		a = strings.ToLower(a)
		b = strings.ToLower(b)
	}
	for _, left := range []string{a, a + "-wal", a + "-shm", a + "-journal", a + ".owner"} {
		for _, right := range []string{b, b + "-wal", b + "-shm", b + "-journal"} {
			if left == right || strings.HasPrefix(left, right+string(filepath.Separator)) || strings.HasPrefix(right, left+string(filepath.Separator)) {
				return false
			}
		}
	}
	return true
}

func (p *SQLiteStatePlan) Configs() (StateConfigs, error) {
	if p == nil || p.state.MinimumControlRevision == 0 {
		return StateConfigs{}, ErrProfile
	}
	c := p.state
	c.Control.Services = map[string][]string{}
	for id, paths := range p.state.Control.Services {
		c.Control.Services[id] = slices.Clone(paths)
	}
	c.Registry.SharedPaths = slices.Clone(c.Registry.SharedPaths)
	c.Registry.ReservedAPIPrefixes = slices.Clone(c.Registry.ReservedAPIPrefixes)
	c.Registry.Services = map[string]registry.ServiceConfig{}
	for id, service := range p.state.Registry.Services {
		service.AllowedPaths = slices.Clone(service.AllowedPaths)
		if service.ActivePassive != nil {
			original := service.ActivePassive
			pool := *original
			pool.Orders = map[string][]string{}
			for version, order := range original.Orders {
				pool.Orders[version] = slices.Clone(order)
			}
			if original.HoldDown != nil {
				hold := *original.HoldDown
				pool.HoldDown = &hold
			}
			service.ActivePassive = &pool
		}
		c.Registry.Services[id] = service
	}
	return c, nil
}

// Bind assigns only component state fields; all other runtime inputs remain
// caller-composed. Existing state overrides are rejected, not silently replaced.
func (p *SQLiteStatePlan) Bind(base gateway.Config) (gateway.Config, error) {
	if !reflect.ValueOf(base.Tunnel.Control).IsZero() || !reflect.ValueOf(base.Tunnel.Registry).IsZero() || !reflect.ValueOf(base.Tunnel.Replay).IsZero() || base.Tunnel.MinimumControlRevision != 0 {
		return gateway.Config{}, ErrProfile
	}
	c, err := p.Configs()
	if err != nil {
		return gateway.Config{}, err
	}
	base.Tunnel.Control = c.Control
	base.Tunnel.Registry = c.Registry
	base.Tunnel.Replay = c.Replay
	base.Tunnel.MinimumControlRevision = c.MinimumControlRevision
	return base, nil
}
