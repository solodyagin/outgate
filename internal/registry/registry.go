// Package registry models gateway route ownership and selection. Callers own
// authentication, durable publication, transport lifecycle and HTTP delivery.
package registry

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

var (
	ErrInvalid          = errors.New("invalid registry input")
	ErrUnknownService   = errors.New("unknown service")
	ErrDuplicate        = errors.New("instance ID already in use")
	ErrPathForbidden    = errors.New("path forbidden")
	ErrPathConflict     = errors.New("path already owned")
	ErrQuota            = errors.New("registry quota exceeded")
	ErrRevisionConflict = errors.New("revision conflict")
	ErrConflict         = errors.New("registry state conflict")
	ErrClosedSession    = errors.New("session no longer registered")
)

type RouteState string

const (
	Pending RouteState = "pending"
	Active  RouteState = "active"
	Retired RouteState = "retired"
)

type Transport string

const (
	QUIC Transport = "quic"
	WSS  Transport = "wss"
)

type Rollout struct {
	Stable         string
	Canary         string
	CanaryPercent  int
	PreviousStable string
}

type ActivePassive struct {
	Orders  map[string][]string
	Preempt bool
	// A nil HoldDown uses 30 seconds. An explicit zero allows immediate preemption.
	HoldDown *time.Duration
}

type ServiceConfig struct {
	AllowedPaths  []string
	Rollout       Rollout
	ActivePassive *ActivePassive
}

type Config struct {
	Development          bool
	Services             map[string]ServiceConfig
	SharedPaths          []string
	ReservedAPIPrefixes  []string
	FrontendService      string
	FrontendEnabled      bool
	MaxPathsPerInstance  int
	MaxTunnels           int
	MaxTunnelsPerService int
	MaxVersions          int
}

type Registry struct {
	mu   sync.Mutex
	now  func() time.Time
	draw func(int) int

	development bool
	frontend    string
	frontendOn  bool
	reserved    map[string]struct{}
	shared      map[string]struct{}
	// Retain released paths in development to prevent a later registration
	// from automatically republishing the path.
	released map[string]struct{}
	routes   map[string]*route
	services map[string]*service
	sessions map[string]*Session

	publicationBlocked bool
	pendingPublication *Registry

	revision      uint64
	maxPaths      int
	maxTunnels    int
	maxPerService int
	maxVersions   int
}

type route struct {
	owners map[string]RouteState
	next   uint64
}

type service struct {
	config        ServiceConfig
	rollout       Rollout
	routeRevision uint64
	versions      map[string]*version
	tunnels       int
}

type version struct {
	firstSeen  time.Time
	lastSeen   time.Time
	pathMode   string
	rewrite    bool
	mounts     map[string]string
	paths      map[string]struct{}
	transports map[Transport]struct{}
	sessions   map[string]*Session
	retired    bool
	next       uint64
	primary    *Session
}

// Session identifies a single registration. An instance ID may be reused after
// cleanup, but a stale Session handle can never mutate its replacement.
type Session struct {
	info           Instance
	paths          map[string]struct{}
	ready          bool
	readySince     time.Time
	draining       bool
	transportBound bool
}

type Instance struct {
	ServiceID           string
	InstanceID          string
	Version             string
	Transport           Transport
	PathMode            string
	RewriteMountHeaders bool
}

func (s *Session) Instance() Instance { return s.info }

type Registration struct {
	Session       *Session
	Discovered    bool
	Paths         map[string]RouteState
	RouteRevision uint64
}

var (
	serviceID  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	instanceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

func New(config Config) (*Registry, error) {
	return newRegistry(config, time.Now, rand.IntN)
}

func newRegistry(config Config, now func() time.Time, draw func(int) int) (*Registry, error) {
	if config.MaxPathsPerInstance < 0 || config.MaxPathsPerInstance > 32 ||
		config.MaxTunnels < 0 || config.MaxTunnelsPerService < 0 || config.MaxVersions < 0 {
		return nil, ErrInvalid
	}
	api, err := prefixes(config.ReservedAPIPrefixes, false)
	if err != nil {
		return nil, err
	}
	api["/api"] = struct{}{}
	shared, err := prefixes(config.SharedPaths, false)
	if err != nil {
		return nil, err
	}
	r := &Registry{
		now: now, draw: draw, development: config.Development,
		frontend: config.FrontendService, frontendOn: config.FrontendEnabled,
		reserved: api, shared: shared, released: make(map[string]struct{}),
		routes: make(map[string]*route), services: make(map[string]*service), sessions: make(map[string]*Session),
		maxPaths: defaultLimit(config.MaxPathsPerInstance, 32), maxTunnels: defaultLimit(config.MaxTunnels, 1000),
		maxPerService: defaultLimit(config.MaxTunnelsPerService, 16), maxVersions: defaultLimit(config.MaxVersions, 100),
	}
	if config.FrontendEnabled && config.FrontendService == "" {
		return nil, ErrInvalid
	}
	for id, cfg := range config.Services {
		allowed, err := prefixes(cfg.AllowedPaths, true)
		_, root := allowed["/"]
		if err != nil || len(allowed) == 0 || !serviceID.MatchString(id) || root != (id == r.frontend) ||
			cfg.Rollout.PreviousStable != "" || !validRollout(cfg.Rollout) {
			return nil, fmt.Errorf("%w: service configuration", ErrInvalid)
		}
		cfg.AllowedPaths = slices.Sorted(maps.Keys(allowed))
		if cfg.ActivePassive != nil {
			pool, err := copyPools(*cfg.ActivePassive, cfg.Rollout)
			if err != nil {
				return nil, err
			}
			cfg.ActivePassive = &pool
		}
		r.services[id] = &service{config: cfg, rollout: cfg.Rollout, versions: make(map[string]*version)}
	}
	if r.frontend != "" && r.services[r.frontend] == nil {
		return nil, fmt.Errorf("%w: unknown frontend service", ErrInvalid)
	}
	return r, nil
}

func defaultLimit(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func prefixes(paths []string, allowRoot bool) (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(paths))
	for _, raw := range paths {
		path, err := v1.NormalizePrefix(raw)
		if err != nil || path == "/" && !allowRoot {
			return nil, ErrInvalid
		}
		if _, exists := out[path]; exists {
			return nil, ErrInvalid
		}
		out[path] = struct{}{}
	}
	return out, nil
}

func copyPools(pool ActivePassive, policy Rollout) (ActivePassive, error) {
	if pool.HoldDown != nil && *pool.HoldDown < 0 || len(pool.Orders) == 0 {
		return ActivePassive{}, ErrInvalid
	}
	orders := make(map[string][]string, len(pool.Orders))
	seen := make(map[string]bool)
	for name, order := range pool.Orders {
		if !validVersion(name) || len(order) == 0 {
			return ActivePassive{}, ErrInvalid
		}
		for _, id := range order {
			if !instanceID.MatchString(id) || seen[id] {
				return ActivePassive{}, ErrInvalid
			}
			seen[id] = true
		}
		orders[name] = slices.Clone(order)
	}
	for _, name := range weightedVersions(policy) {
		if len(orders[name]) == 0 {
			return ActivePassive{}, ErrInvalid
		}
	}
	pool.Orders = orders
	holdDown := 30 * time.Second
	if pool.HoldDown != nil {
		holdDown = *pool.HoldDown
	}
	pool.HoldDown = &holdDown
	return pool, nil
}

func validVersion(value string) bool {
	return len(value) <= 128 && utf8.ValidString(value) &&
		strings.TrimSpace(value) != "" && !strings.ContainsFunc(value, unicode.IsControl)
}

// RegisterAuthorized is the entry point after the caller has verified identity
// and the complete credential binding. A successful registration starts unready.
func (r *Registry) RegisterAuthorized(reg v1.Register, transport Transport) (Registration, error) {
	if reg.Validate() != nil || transport != QUIC && transport != WSS {
		return Registration{}, ErrInvalid
	}
	paths, err := prefixes(reg.Paths, true)
	if err != nil {
		return Registration{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.publicationBlocked {
		return Registration{}, ErrPublicationUnavailable
	}
	s := r.services[reg.ServiceID]
	if s == nil {
		return Registration{}, ErrUnknownService
	}
	if r.sessions[reg.InstanceID] != nil {
		return Registration{}, ErrDuplicate
	}
	if len(paths) > r.maxPaths || len(r.sessions) >= r.maxTunnels || s.tunnels >= r.maxPerService || r.revision == math.MaxUint64 {
		return Registration{}, ErrQuota
	}
	versions := s.versions
	current := versions[reg.Version]
	if current == nil && liveVersionCount(versions) >= r.maxVersions {
		return Registration{}, ErrQuota
	}
	if err := r.checkRegistration(s, current, reg, paths); err != nil {
		return Registration{}, err
	}

	now := r.now()
	discovered := current == nil
	var updated version
	if discovered {
		updated = version{
			firstSeen: now, pathMode: reg.PathMode, rewrite: reg.RewriteMountHeaders,
			mounts: make(map[string]string), paths: make(map[string]struct{}),
			transports: make(map[Transport]struct{}), sessions: make(map[string]*Session),
		}
	} else {
		updated = *current
		updated.mounts = maps.Clone(current.mounts)
	}
	for id, raw := range reg.Mounts {
		path, _ := v1.NormalizePrefix(raw) // Register.Validate checked exact membership in Paths.
		if existing, found := updated.mounts[id]; found && existing != path {
			return Registration{}, ErrInvalid
		}
		updated.mounts[id] = path
	}

	before := r.discovery(s, reg.ServiceID)
	states := make(map[string]RouteState, len(paths))
	ownershipChanged := false
	for path := range paths {
		state := r.state(reg.ServiceID, path)
		if state == "" {
			state = Pending
			_, released := r.released[path]
			if r.development && !released && reg.Version == s.config.Rollout.Stable && weight(s.rollout, reg.Version) > 0 {
				state = Active
			}
			ownershipChanged = true
		}
		states[path] = state
	}
	if !r.compatibleMounts(s, reg.ServiceID, s.rollout, reg.Version, &updated, states) {
		return Registration{}, ErrConflict
	}

	session := &Session{info: Instance{
		ServiceID: reg.ServiceID, InstanceID: reg.InstanceID, Version: reg.Version, Transport: transport,
		PathMode: reg.PathMode, RewriteMountHeaders: reg.RewriteMountHeaders,
	}, paths: paths}
	for path, state := range states {
		entry := r.routes[path]
		if entry == nil {
			entry = &route{owners: make(map[string]RouteState)}
			r.routes[path] = entry
		}
		entry.owners[reg.ServiceID] = state
		updated.paths[path] = struct{}{}
	}
	updated.lastSeen = now
	updated.transports[transport] = struct{}{}
	updated.sessions[reg.InstanceID] = session
	versions[reg.Version] = &updated
	r.sessions[reg.InstanceID] = session
	s.tunnels++
	r.revision++
	if ownershipChanged || !maps.Equal(before, r.discovery(s, reg.ServiceID)) {
		s.routeRevision++
	}
	return Registration{Session: session, Discovered: discovered, Paths: states, RouteRevision: s.routeRevision}, nil
}

func liveVersionCount(versions map[string]*version) int {
	count := 0
	for _, v := range versions {
		if !v.retired {
			count++
		}
	}
	return count
}

func (r *Registry) checkRegistration(s *service, current *version, reg v1.Register, paths map[string]struct{}) error {
	if current != nil && (current.retired || current.pathMode != reg.PathMode || current.rewrite != reg.RewriteMountHeaders) {
		return ErrInvalid
	}
	if pool := s.config.ActivePassive; pool != nil {
		if !slices.Contains(pool.Orders[reg.Version], reg.InstanceID) || !r.development && !reg.ReadinessCheckConfigured {
			return ErrInvalid
		}
		if current != nil {
			for _, existing := range current.sessions {
				if !maps.Equal(paths, existing.paths) {
					return ErrInvalid
				}
			}
		}
	}
	for path := range paths {
		if path == "/" && (reg.ServiceID != r.frontend || !r.frontendOn) {
			return ErrPathForbidden
		}
		if !slices.ContainsFunc(s.config.AllowedPaths, func(allowed string) bool {
			return allowed == path || allowed != "/" && v1.MatchesPrefix(allowed, path)
		}) {
			return ErrPathForbidden
		}
		if entry := r.routes[path]; entry != nil {
			if entry.owners[reg.ServiceID] == Retired {
				return ErrPathForbidden
			}
			if _, shared := r.shared[path]; !shared && entry.owners[reg.ServiceID] == "" {
				return ErrPathConflict
			}
		}
	}
	return nil
}

func (r *Registry) state(serviceID, path string) RouteState {
	if entry := r.routes[path]; entry != nil {
		return entry.owners[serviceID]
	}
	return ""
}

func (r *Registry) Revision() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revision
}

func (r *Registry) checkRevision(expected uint64) error {
	if r.publicationBlocked {
		return ErrPublicationUnavailable
	}
	if r.revision != expected {
		return ErrRevisionConflict
	}
	if expected == math.MaxUint64 {
		return ErrQuota
	}
	return nil
}

type VersionInfo struct {
	Version    string
	FirstSeen  time.Time
	LastSeen   time.Time
	Instances  int
	Paths      []string
	Transports []Transport
	Retired    bool
}

func (r *Registry) Versions(serviceID string) ([]VersionInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.services[serviceID]
	if s == nil {
		return nil, ErrUnknownService
	}
	out := make([]VersionInfo, 0, len(s.versions))
	for _, name := range slices.Sorted(maps.Keys(s.versions)) {
		v := s.versions[name]
		active := 0
		for _, session := range v.sessions {
			if !r.publicationBlocked && session.available() {
				active++
			}
		}
		out = append(out, VersionInfo{
			Version: name, FirstSeen: v.firstSeen, LastSeen: v.lastSeen, Instances: active, Retired: v.retired,
			Paths: slices.Sorted(maps.Keys(v.paths)), Transports: slices.Sorted(maps.Keys(v.transports)),
		})
	}
	return out, nil
}
