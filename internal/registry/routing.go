package registry

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

// Decision contains either a selected tunnel, an upstream decision, or an HTTP
// error status. Selection is a snapshot; it does not reserve a transport stream.
type Decision struct {
	Session           *Session
	Upstream          bool
	Status            int
	RetryAfterSeconds int
	Prefix            string
	ServiceID         string
	Version           string
	RouteRevision     uint64
}

// Lookup takes the original escaped request URI. A target and expected revision
// may only come from an already authenticated, authorized interservice request.
func (r *Registry) Lookup(rawURI, target string, expected *uint64) Decision {
	path, err := v1.DecodeRoutePath(rawURI)
	if err != nil || target == "" && expected != nil {
		return Decision{Status: http.StatusBadRequest}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if expected != nil {
		s := r.services[target]
		if s == nil {
			return Decision{Status: http.StatusForbidden}
		}
		if *expected != s.routeRevision {
			return Decision{Status: http.StatusConflict}
		}
	}
	now := r.now()
	prefix, entry := r.longestRoute(path)
	if entry == nil {
		for reserved := range r.reserved {
			if v1.MatchesPrefix(reserved, path) {
				if target != "" {
					return r.missingTargetRoute(target)
				}
				return Decision{Status: http.StatusNotFound}
			}
		}
		if r.frontendOn && (target == "" || target == r.frontend) && r.state(r.frontend, "/") == Active {
			prefix, entry = "/", r.routes["/"]
		} else if target == "" {
			return Decision{Upstream: true}
		} else {
			return r.missingTargetRoute(target)
		}
	}

	decision := Decision{Prefix: prefix}
	if target != "" {
		switch entry.owners[target] {
		case Active:
		case Retired:
			return unavailable(decision)
		default:
			decision.Status = http.StatusForbidden
			return decision
		}
	} else {
		owners := make([]string, 0, len(entry.owners))
		for id, state := range entry.owners {
			if state == Active && r.ownerAvailable(r.services[id], prefix, now) {
				owners = append(owners, id)
			}
		}
		if len(owners) == 0 {
			return unavailable(decision)
		}
		slices.Sort(owners)
		target = owners[entry.next%uint64(len(owners))]
		entry.next++
	}

	s := r.services[target]
	decision.ServiceID, decision.RouteRevision = target, s.routeRevision
	decision.Version = s.rollout.Stable
	switch {
	case s.rollout.CanaryPercent == 100:
		decision.Version = s.rollout.Canary
	case s.rollout.CanaryPercent > 0:
		if r.draw(100) < s.rollout.CanaryPercent {
			decision.Version = s.rollout.Canary
		}
	}
	decision.Session = r.pickSession(s, decision.Version, prefix, now)
	if decision.Session == nil {
		return unavailable(decision)
	}
	return decision
}

func (r *Registry) missingTargetRoute(target string) Decision {
	if r.services[target] == nil {
		return Decision{Status: http.StatusForbidden}
	}
	return unavailable(Decision{ServiceID: target})
}

func unavailable(d Decision) Decision {
	d.Status = http.StatusServiceUnavailable
	d.RetryAfterSeconds = 1
	return d
}

func (r *Registry) longestRoute(path string) (string, *route) {
	for prefix := strings.TrimSuffix(path, "/"); prefix != ""; {
		if entry := r.routes[prefix]; entry != nil {
			for _, state := range entry.owners {
				if state == Active || state == Retired {
					return prefix, entry
				}
			}
		}
		prefix = prefix[:strings.LastIndexByte(prefix, '/')]
	}
	return "", nil
}

func (r *Registry) ownerAvailable(s *service, path string, now time.Time) bool {
	for _, name := range weightedVersions(s.rollout) {
		if r.versionCovers(s, name, path, now) {
			return true
		}
	}
	return false
}

func (r *Registry) versionCovers(s *service, name, path string, now time.Time) bool {
	v := s.versions[name]
	if v == nil || v.retired {
		return false
	}
	if s.config.ActivePassive != nil {
		return choosePrimary(v, s.config.ActivePassive, name, now).serves(path)
	}
	for _, session := range v.sessions {
		if session.serves(path) {
			return true
		}
	}
	return false
}

func (r *Registry) pickSession(s *service, name, path string, now time.Time) *Session {
	v := s.versions[name]
	if v == nil || v.retired {
		return nil
	}
	if s.config.ActivePassive != nil {
		primary := r.primary(s, name, now)
		if primary.serves(path) {
			return primary
		}
		return nil
	}
	ready := make([]string, 0, len(v.sessions))
	for id, candidate := range v.sessions {
		if candidate.serves(path) {
			ready = append(ready, id)
		}
	}
	if len(ready) == 0 {
		return nil
	}
	slices.Sort(ready)
	selected := v.sessions[ready[v.next%uint64(len(ready))]]
	v.next++
	return selected
}

func (s *Session) available() bool { return s != nil && s.ready && !s.draining }

func (s *Session) serves(path string) bool {
	if !s.available() {
		return false
	}
	_, found := s.paths[path]
	return found
}

func (r *Registry) primary(s *service, name string, now time.Time) *Session {
	v := s.versions[name]
	v.primary = choosePrimary(v, s.config.ActivePassive, name, now)
	return v.primary
}

func choosePrimary(v *version, pool *ActivePassive, name string, now time.Time) *Session {
	current := v.primary
	for _, id := range pool.Orders[name] {
		candidate := v.sessions[id]
		switch {
		case !candidate.available():
			continue
		case !current.available():
			return candidate
		case candidate == current:
			return current
		case pool.Preempt && now.Sub(candidate.readySince) >= *pool.HoldDown:
			return candidate
		}
	}
	return nil
}

// SetReady consumes readiness already determined by the session lifecycle.
// Adapters use it for readiness, stale status, revocation and expiry.
func (r *Registry) SetReady(session *Session, ready bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, _, err := r.sessionVersion(session)
	if err != nil {
		return err
	}
	if session.draining && ready {
		return ErrConflict
	}
	if session.ready == ready {
		return nil
	}
	now := r.now()
	session.ready = ready
	if ready {
		session.readySince = now
	} else {
		session.readySince = time.Time{}
	}
	if s.config.ActivePassive != nil {
		r.primary(s, session.info.Version, now)
	}
	return nil
}

func (r *Registry) Drain(session *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, _, err := r.sessionVersion(session)
	if err != nil {
		return err
	}
	session.draining = true
	if s.config.ActivePassive != nil {
		r.primary(s, session.info.Version, r.now())
	}
	return nil
}

func (r *Registry) Disconnect(session *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, v, err := r.sessionVersion(session)
	if err != nil {
		return err
	}
	session.draining = true
	delete(r.sessions, session.info.InstanceID)
	delete(v.sessions, session.info.InstanceID)
	s.tunnels--
	if s.config.ActivePassive != nil {
		r.primary(s, session.info.Version, r.now())
	}
	return nil
}

func (r *Registry) sessionVersion(session *Session) (*service, *version, error) {
	if session == nil || r.sessions[session.info.InstanceID] != session {
		return nil, nil, ErrClosedSession
	}
	s := r.services[session.info.ServiceID]
	return s, s.versions[session.info.Version], nil
}

type Mount struct {
	Prefix   string
	PathMode string
}

// Discovery returns a detached snapshot for a caller that has already passed
// service identity and discovery authorization checks.
func (r *Registry) Discovery(serviceID string) (map[string]Mount, uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.services[serviceID]
	if s == nil {
		return nil, 0, ErrUnknownService
	}
	return r.discovery(s, serviceID), s.routeRevision, nil
}

func (r *Registry) discovery(s *service, id string) map[string]Mount {
	var common map[string]Mount
	for _, name := range weightedVersions(s.rollout) {
		v := s.versions[name]
		if v == nil {
			return map[string]Mount{}
		}
		mounts := r.activeMounts(id, v, nil)
		if common == nil {
			common = mounts
		} else {
			maps.DeleteFunc(common, func(id string, mount Mount) bool { return mounts[id] != mount })
		}
	}
	return common
}

func (r *Registry) activeMounts(id string, v *version, change map[string]RouteState) map[string]Mount {
	result := make(map[string]Mount)
	for name, path := range v.mounts {
		state, edited := change[path]
		if (!edited && r.state(id, path) == Active) || (edited && state == Active) {
			result[name] = Mount{Prefix: path, PathMode: v.pathMode}
		}
	}
	return result
}

// Registration can discover another replica with a subset of a version's
// mounts. It must never make an existing mount ambiguous between versions.
func (r *Registry) compatibleMounts(s *service, id string, policy Rollout, registering string, candidate *version, states map[string]RouteState) bool {
	seen := make(map[string]Mount)
	for _, name := range weightedVersions(policy) {
		v := s.versions[name]
		if name == registering {
			v = candidate
		}
		if v == nil {
			continue
		}
		for key, mount := range r.activeMounts(id, v, states) {
			if prior, ok := seen[key]; ok && prior != mount {
				return false
			}
			seen[key] = mount
		}
	}
	return true
}

func (r *Registry) consistentMounts(s *service, id string, policy Rollout, states map[string]RouteState) bool {
	var previous map[string]Mount
	for _, name := range weightedVersions(policy) {
		v := s.versions[name]
		if v == nil {
			// Bootstrap versions can be absent before their first registration.
			continue
		}
		current := r.activeMounts(id, v, states)
		if previous != nil && !maps.Equal(previous, current) {
			return false
		}
		previous = current
	}
	return true
}
