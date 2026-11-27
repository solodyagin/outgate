package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

// MaxSnapshotBytes bounds the internal recovery document before decoding. Store
// readers must enforce the same bound before allocating a database/blob result.
const MaxSnapshotBytes = 1 << 20

var ErrSnapshot = errors.New("invalid or oversized registry snapshot")

// These types are private persistence data, not wire or Admin API contracts.
// Runtime ownership, readiness, transport bindings and counters are not restored.
type registrySnapshot struct {
	Format     int                              `json:"format"`
	Revision   uint64                           `json:"revision,string"`
	Policy     snapshotPolicy                   `json:"policy"`
	FrontendOn bool                             `json:"frontend_enabled"`
	Released   []string                         `json:"released"`
	Routes     map[string]map[string]RouteState `json:"routes"`
	Services   map[string]snapshotService       `json:"services"`
}

type snapshotPolicy struct {
	Development bool                             `json:"development"`
	Frontend    string                           `json:"frontend"`
	Reserved    []string                         `json:"reserved"`
	Shared      []string                         `json:"shared"`
	Services    map[string]snapshotServicePolicy `json:"services"`
}

type snapshotServicePolicy struct {
	AllowedPaths []string       `json:"allowed_paths"`
	Pool         *ActivePassive `json:"active_passive"`
}

type snapshotService struct {
	Rollout       Rollout                    `json:"rollout"`
	RouteRevision uint64                     `json:"route_revision,string"`
	Versions      map[string]snapshotVersion `json:"versions"`
}

type snapshotVersion struct {
	FirstSeen  time.Time         `json:"first_seen"`
	LastSeen   time.Time         `json:"last_seen"`
	PathMode   string            `json:"path_mode"`
	Rewrite    bool              `json:"rewrite_mount_headers"`
	Mounts     map[string]string `json:"mounts"`
	Paths      []string          `json:"paths"`
	Transports []Transport       `json:"transports"`
	Retired    bool              `json:"retired"`
}

func (r *Registry) snapshotPolicy() snapshotPolicy {
	p := snapshotPolicy{
		Development: r.development, Frontend: r.frontend,
		Reserved: slices.Sorted(maps.Keys(r.reserved)), Shared: slices.Sorted(maps.Keys(r.shared)),
		Services: make(map[string]snapshotServicePolicy, len(r.services)),
	}
	for id, s := range r.services {
		p.Services[id] = snapshotServicePolicy{s.config.AllowedPaths, s.config.ActivePassive}
	}
	return p
}

type snapshotBuffer struct{ bytes.Buffer }

func (b *snapshotBuffer) Write(p []byte) (int, error) {
	if len(p) > MaxSnapshotBytes-b.Len() {
		return 0, ErrSnapshot
	}
	return b.Buffer.Write(p)
}

func encodeSnapshot(s registrySnapshot) ([]byte, error) {
	var b snapshotBuffer
	if err := json.NewEncoder(&b).Encode(s); err != nil {
		return nil, ErrSnapshot
	}
	return b.Bytes(), nil
}

// MarshalSnapshot captures a detached, canonical recovery document under the
// registry lock. It does not commit it or make a mutation durable. A publication
// owner must serialize mutation, SQL revision/outbox commit and resync, and must
// not acknowledge a registration based on this method alone.
func (r *Registry) MarshalSnapshot() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	snapshot := registrySnapshot{
		Format: 1, Revision: r.revision, Policy: r.snapshotPolicy(), FrontendOn: r.frontendOn,
		Released: slices.Sorted(maps.Keys(r.released)), Routes: make(map[string]map[string]RouteState, len(r.routes)),
		Services: make(map[string]snapshotService, len(r.services)),
	}
	for path, entry := range r.routes {
		snapshot.Routes[path] = entry.owners
	}
	for id, s := range r.services {
		stored := snapshotService{Rollout: s.rollout, RouteRevision: s.routeRevision, Versions: make(map[string]snapshotVersion, len(s.versions))}
		for name, v := range s.versions {
			stored.Versions[name] = snapshotVersion{
				FirstSeen: v.firstSeen, LastSeen: v.lastSeen, PathMode: v.pathMode, Rewrite: v.rewrite,
				Mounts: v.mounts, Paths: slices.Sorted(maps.Keys(v.paths)), Transports: slices.Sorted(maps.Keys(v.transports)), Retired: v.retired,
			}
		}
		snapshot.Services[id] = stored
	}
	return encodeSnapshot(snapshot)
}

// RestoreSnapshot creates an isolated registry with no sessions or readiness.
// Trusted deployment permissions must match; incompatible configuration needs
// an explicit control-plane migration, never a silent ownership reset. Stored
// rollout/root state overrides bootstrap YAML. This checks internal consistency,
// not authenticity, epoch, freshness or durability; the storage owner must check
// those before publishing the result or lifting its recovery barrier.
func RestoreSnapshot(config Config, data []byte) (*Registry, error) {
	if len(data) == 0 || len(data) > MaxSnapshotBytes {
		return nil, ErrSnapshot
	}
	var stored registrySnapshot
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&stored) != nil {
		return nil, ErrSnapshot
	}
	// Only the exact internal encoding is accepted. This also rejects duplicate
	// keys, lossy UTF-8, omitted fields and trailing values before publication.
	canonical, err := encodeSnapshot(stored)
	if err != nil || !bytes.Equal(data, canonical) || stored.Format != 1 {
		return nil, ErrSnapshot
	}
	r, err := New(config)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(stored.Policy, r.snapshotPolicy()) || len(stored.Services) != len(r.services) ||
		stored.FrontendOn && r.frontend == "" || !r.development && len(stored.Released) != 0 {
		return nil, ErrSnapshot
	}
	r.revision, r.frontendOn = stored.Revision, stored.FrontendOn
	for id, saved := range stored.Services {
		s := r.services[id]
		if s == nil || saved.RouteRevision > stored.Revision || !validRollout(saved.Rollout) ||
			saved.Rollout.PreviousStable != "" && !validVersion(saved.Rollout.PreviousStable) {
			return nil, ErrSnapshot
		}
		if s.config.ActivePassive != nil {
			if _, err := copyPools(*s.config.ActivePassive, saved.Rollout); err != nil {
				return nil, ErrSnapshot
			}
		}
		s.rollout, s.routeRevision = saved.Rollout, saved.RouteRevision
		for name, v := range saved.Versions {
			if !validVersion(name) || v.FirstSeen.IsZero() || v.LastSeen.Before(v.FirstSeen) ||
				v.PathMode != "preserve" && v.PathMode != "strip" || len(v.Paths) == 0 || len(v.Transports) == 0 ||
				v.Retired && (name == s.rollout.Stable || name == s.rollout.Canary || name == s.rollout.PreviousStable) {
				return nil, ErrSnapshot
			}
			paths, err := canonicalPaths(v.Paths, true)
			if err != nil {
				return nil, err
			}
			for path := range paths {
				if !allowedSnapshotPath(s, path) || path == "/" && id != r.frontend {
					return nil, ErrSnapshot
				}
			}
			for key, path := range v.Mounts {
				if _, found := paths[path]; !found || !snapshotMountID.MatchString(key) {
					return nil, ErrSnapshot
				}
			}
			transports := make(map[Transport]struct{})
			for _, transport := range v.Transports {
				if transport != QUIC && transport != WSS {
					return nil, ErrSnapshot
				}
				transports[transport] = struct{}{}
			}
			if !slices.Equal(v.Transports, slices.Sorted(maps.Keys(transports))) {
				return nil, ErrSnapshot
			}
			s.versions[name] = &version{
				firstSeen: v.FirstSeen, lastSeen: v.LastSeen, pathMode: v.PathMode, rewrite: v.Rewrite,
				mounts: v.Mounts, paths: paths, transports: transports, retired: v.Retired, sessions: make(map[string]*Session),
			}
		}
		if liveVersionCount(s.versions) > r.maxVersions || len(s.versions) > 0 && (stored.Revision == 0 || s.routeRevision == 0) {
			return nil, ErrSnapshot
		}
	}
	for path, owners := range stored.Routes {
		if _, err := canonicalPaths([]string{path}, true); err != nil || len(owners) == 0 ||
			len(owners) > 1 && !slices.Contains(stored.Policy.Shared, path) {
			return nil, ErrSnapshot
		}
		for id, state := range owners {
			s := r.services[id]
			if s == nil || !allowedSnapshotPath(s, path) || s.routeRevision == 0 ||
				state != Pending && state != Active && state != Retired ||
				path == "/" && (id != r.frontend || !r.frontendOn || state == Retired) {
				return nil, ErrSnapshot
			}
			covered := false
			for _, v := range s.versions {
				_, found := v.paths[path]
				covered = covered || found
			}
			if !covered {
				return nil, ErrSnapshot
			}
		}
		r.routes[path] = &route{owners: owners}
	}
	for id, s := range r.services {
		// Registration permits a weighted version to know additional mounts
		// while discovery exposes only the common subset. Reject ambiguity,
		// not a valid intermediate registration with unequal mount sets.
		if !r.compatibleMounts(s, id, s.rollout, "", nil, nil) {
			return nil, ErrSnapshot
		}
		for _, v := range s.versions {
			for _, path := range v.mounts {
				if r.state(id, path) == "" {
					return nil, ErrSnapshot
				}
			}
		}
	}
	released, err := canonicalPaths(stored.Released, false)
	if err != nil {
		return nil, err
	}
	r.released = released
	return r, nil
}

var snapshotMountID = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func allowedSnapshotPath(s *service, path string) bool {
	return slices.ContainsFunc(s.config.AllowedPaths, func(allowed string) bool {
		return allowed == path || allowed != "/" && v1.MatchesPrefix(allowed, path)
	})
}

func canonicalPaths(paths []string, root bool) (map[string]struct{}, error) {
	set, err := prefixes(paths, root)
	if err != nil || !slices.Equal(paths, slices.Sorted(maps.Keys(set))) {
		return nil, ErrSnapshot
	}
	for path := range set {
		normalized, err := v1.NormalizePrefix(path)
		if err != nil || normalized != path {
			return nil, ErrSnapshot
		}
	}
	return set, nil
}
