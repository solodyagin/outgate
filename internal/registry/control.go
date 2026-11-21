package registry

import (
	"maps"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

func validRollout(policy Rollout) bool {
	return validVersion(policy.Stable) && policy.CanaryPercent >= 0 && policy.CanaryPercent <= 100 &&
		((policy.Canary == "" && policy.CanaryPercent == 0) ||
			(validVersion(policy.Canary) && policy.Stable != policy.Canary))
}

func weightedVersions(policy Rollout) []string {
	switch policy.CanaryPercent {
	case 0:
		return []string{policy.Stable}
	case 100:
		return []string{policy.Canary}
	default:
		return []string{policy.Stable, policy.Canary}
	}
}

func weight(policy Rollout, name string) int {
	switch name {
	case policy.Stable:
		return 100 - policy.CanaryPercent
	case policy.Canary:
		return policy.CanaryPercent
	default:
		return 0
	}
}

func (r *Registry) Rollout(serviceID string) (Rollout, uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.services[serviceID]
	if s == nil {
		return Rollout{}, 0, ErrUnknownService
	}
	return s.rollout, r.revision, nil
}

// Mutating methods consume an expected control revision. Callers are responsible
// for authenticating commands and committing durable state and audit records.
func (r *Registry) UpdateRolloutAuthorized(id string, policy Rollout, expected uint64) error {
	if !validRollout(policy) || policy.PreviousStable != "" {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.serviceForChange(id, expected)
	if err != nil {
		return err
	}
	policy.PreviousStable = s.rollout.PreviousStable
	// An explicit PUT can keep the bootstrapped stable version, and can set
	// canary to 0 without requiring any running instance of that canary.
	if policy.Canary != "" && policy.Canary != s.rollout.Canary && s.versions[policy.Canary] == nil {
		return ErrConflict
	}
	for _, name := range []string{policy.Stable, policy.Canary} {
		if version := s.versions[name]; version != nil && version.retired {
			return ErrConflict
		}
	}
	now := r.now()
	versionsToCheck := weightedVersions(policy)
	if policy.CanaryPercent == 100 && policy.Stable != s.rollout.Stable {
		versionsToCheck = append(versionsToCheck, policy.Stable)
	}
	for _, name := range versionsToCheck {
		if s.config.ActivePassive != nil && len(s.config.ActivePassive.Orders[name]) == 0 {
			return ErrConflict
		}
		if weight(s.rollout, name) == 0 || name == policy.Stable && name != s.rollout.Stable {
			if !r.coversService(s, id, name, now) {
				return ErrConflict
			}
		}
	}
	return r.publishRollout(s, id, policy)
}

func (r *Registry) PromoteAuthorized(id string, expected uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.serviceForChange(id, expected)
	if err != nil {
		return err
	}
	if s.rollout.Canary == "" || !r.coversService(s, id, s.rollout.Canary, r.now()) {
		return ErrConflict
	}
	return r.publishRollout(s, id, Rollout{Stable: s.rollout.Canary, PreviousStable: s.rollout.Stable})
}

func (r *Registry) RollbackAuthorized(id string, expected uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.serviceForChange(id, expected)
	if err != nil {
		return err
	}
	if s.rollout.Canary != "" {
		return r.publishRollout(s, id, Rollout{Stable: s.rollout.Stable, PreviousStable: s.rollout.PreviousStable})
	}
	if s.rollout.PreviousStable == "" || !r.coversService(s, id, s.rollout.PreviousStable, r.now()) {
		return ErrConflict
	}
	return r.publishRollout(s, id, Rollout{Stable: s.rollout.PreviousStable})
}

func (r *Registry) coversService(s *service, id, name string, now time.Time) bool {
	v := s.versions[name]
	if v == nil || v.retired {
		return false
	}
	ready := false
	for _, session := range v.sessions {
		ready = ready || session.available()
	}
	if !ready {
		return false
	}
	for path, entry := range r.routes {
		state := entry.owners[id]
		if state != Active && state != Pending {
			continue
		}
		if !r.versionCovers(s, name, path, now) {
			return false
		}
	}
	return true
}

func (r *Registry) publishRollout(s *service, id string, policy Rollout) error {
	if !r.consistentMounts(s, id, policy, nil) {
		return ErrConflict
	}
	before := r.discovery(s, id)
	s.rollout = policy
	r.revision++
	if !maps.Equal(before, r.discovery(s, id)) {
		s.routeRevision++
	}
	return nil
}

func (r *Registry) serviceForChange(id string, expected uint64) (*service, error) {
	if err := r.checkRevision(expected); err != nil {
		return nil, err
	}
	s := r.services[id]
	if s == nil {
		return nil, ErrUnknownService
	}
	return s, nil
}

func (r *Registry) ActivateAuthorized(id, rawPath string, expected uint64) error {
	path, err := v1.NormalizePrefix(rawPath)
	if err != nil {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.serviceForChange(id, expected)
	if err != nil {
		return err
	}
	if r.state(id, path) != Pending || path == "/" && (!r.frontendOn || r.frontend != id) {
		return ErrConflict
	}
	now := r.now()
	for _, name := range weightedVersions(s.rollout) {
		if !r.versionCovers(s, name, path, now) {
			return ErrConflict
		}
	}
	if !r.consistentMounts(s, id, s.rollout, map[string]RouteState{path: Active}) {
		return ErrConflict
	}
	r.routes[path].owners[id] = Active
	r.revision++
	s.routeRevision++
	return nil
}

func (r *Registry) RetireAuthorized(id, rawPath string, expected uint64) error {
	path, err := v1.NormalizePrefix(rawPath)
	if err != nil || path == "/" {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.serviceForChange(id, expected)
	if err != nil {
		return err
	}
	state := r.state(id, path)
	if state != Active && state != Pending {
		return ErrConflict
	}
	r.routes[path].owners[id] = Retired
	r.revision++
	s.routeRevision++
	return nil
}

// ReleaseAuthorized accepts proof from the caller that no flows or grants
// still refer to the ownership. The caller must check these under its
// control transaction and serialize them with changes to grants and flows.
func (r *Registry) ReleaseAuthorized(id, rawPath string, expected uint64, flowsDrained, grantsRevoked bool) error {
	path, err := v1.NormalizePrefix(rawPath)
	if err != nil || path == "/" {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.serviceForChange(id, expected)
	if err != nil {
		return err
	}
	if !flowsDrained || !grantsRevoked || r.state(id, path) != Retired {
		return ErrConflict
	}
	r.removeOwner(s, id, path)
	if r.development {
		r.released[path] = struct{}{}
	}
	return nil
}

func (r *Registry) removeOwner(s *service, id, path string) {
	entry := r.routes[path]
	delete(entry.owners, id)
	if len(entry.owners) == 0 {
		delete(r.routes, path)
	}
	for _, v := range s.versions {
		maps.DeleteFunc(v.mounts, func(_, prefix string) bool { return prefix == path })
		for _, session := range v.sessions {
			delete(session.paths, path)
		}
	}
	r.revision++
	s.routeRevision++
}

// SetFrontendEnabledAuthorized changes the permission to register the configured
// root frontend. Production enables routing through a separate activation.
func (r *Registry) SetFrontendEnabledAuthorized(enabled bool, expected uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.serviceForChange(r.frontend, expected)
	if err != nil {
		return err
	}
	r.frontendOn = enabled
	if !enabled && r.state(r.frontend, "/") != "" {
		r.removeOwner(s, r.frontend, "/")
	} else {
		r.revision++
	}
	return nil
}

func (r *Registry) SwitchPrimaryAuthorized(id, name, instance string, expected uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.serviceForChange(id, expected)
	if err != nil {
		return err
	}
	v := s.versions[name]
	if v == nil || v.retired || s.config.ActivePassive == nil {
		return ErrConflict
	}
	session := v.sessions[instance]
	if !session.available() {
		return ErrConflict
	}
	for path, entry := range r.routes {
		if entry.owners[id] == Active && !session.serves(path) {
			return ErrConflict
		}
	}
	v.primary = session
	r.revision++
	return nil
}

func (r *Registry) RetireVersionAuthorized(id, name string, expected uint64, grantsRevoked bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.serviceForChange(id, expected)
	if err != nil {
		return err
	}
	v := s.versions[name]
	if !grantsRevoked || v == nil || v.retired || len(v.sessions) != 0 ||
		name == s.rollout.Stable || name == s.rollout.Canary || name == s.rollout.PreviousStable {
		return ErrConflict
	}
	v.retired = true
	r.revision++
	return nil
}

func (r *Registry) RestoreVersionAuthorized(id, name string, expected uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, err := r.serviceForChange(id, expected)
	if err != nil {
		return err
	}
	v := s.versions[name]
	if v == nil || !v.retired {
		return ErrConflict
	}
	if liveVersionCount(s.versions) >= r.maxVersions {
		return ErrQuota
	}
	v.retired = false
	r.revision++
	return nil
}
