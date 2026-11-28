package registry

import (
	"bytes"
	"errors"
	"maps"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

var ErrPublicationUnavailable = errors.New("registry publication requires verified resync")

// CommitRegistrationAuthorized serializes candidate creation, persistence and
// live publication. persist must atomically commit the snapshot and its audit /
// revision, rechecking admission permissions in that transaction. It runs under
// the registry lock and must not call back into this registry. Use a bounded
// storage context. Authentication, rate limits and transport cleanup are external.
//
// Existing live handles remain valid. The new session starts unready. Any error
// or panic from persist closes selection/dispatch and further durable mutations
// until ReconcileRegistrationAuthorized succeeds. No registration is returned
// on failure, even when the storage commit may actually have completed.
func (r *Registry) CommitRegistrationAuthorized(reg v1.Register, transport Transport, persist func([]byte, uint64) error) (Registration, error) {
	if persist == nil {
		return Registration{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.checkRevision(r.revision); err != nil {
		return Registration{}, err
	}
	candidate := r.registrationCandidate()
	result, err := candidate.RegisterAuthorized(reg, transport)
	if err != nil {
		return Registration{}, err
	}
	data, err := candidate.MarshalSnapshot()
	if err != nil {
		return Registration{}, err
	}
	r.pendingPublication = candidate
	r.publicationBlocked = true
	if err := persist(data, r.revision); err != nil {
		return Registration{}, err
	}
	r.publishRegistration(candidate)
	r.pendingPublication = nil
	r.publicationBlocked = false
	return result, nil
}

// registrationCandidate copies mutable registration metadata while retaining
// exact runtime handles. RegisterAuthorized never changes an existing Session;
// the live registry lock excludes status, selection and cleanup during commit.
func (r *Registry) registrationCandidate() *Registry {
	candidate := &Registry{
		now: r.now, draw: r.draw, development: r.development, frontend: r.frontend, frontendOn: r.frontendOn,
		reserved: r.reserved, shared: r.shared, released: r.released,
		routes: make(map[string]*route, len(r.routes)), services: make(map[string]*service, len(r.services)),
		sessions: maps.Clone(r.sessions), revision: r.revision,
		maxPaths: r.maxPaths, maxTunnels: r.maxTunnels, maxPerService: r.maxPerService, maxVersions: r.maxVersions,
	}
	for path, current := range r.routes {
		copied := *current
		copied.owners = maps.Clone(current.owners)
		candidate.routes[path] = &copied
	}
	for id, current := range r.services {
		copied := *current
		copied.versions = make(map[string]*version, len(current.versions))
		for name, currentVersion := range current.versions {
			copiedVersion := *currentVersion
			copiedVersion.mounts = maps.Clone(currentVersion.mounts)
			copiedVersion.paths = maps.Clone(currentVersion.paths)
			copiedVersion.transports = maps.Clone(currentVersion.transports)
			copiedVersion.sessions = maps.Clone(currentVersion.sessions)
			copied.versions[name] = &copiedVersion
		}
		candidate.services[id] = &copied
	}
	return candidate
}

func (r *Registry) publishRegistration(candidate *Registry) {
	r.routes, r.services, r.sessions, r.revision = candidate.routes, candidate.services, candidate.sessions, candidate.revision
}

// ReconcileRegistrationAuthorized accepts only an independently verified durable
// snapshot of the pre-commit state or the uncertain candidate. It is not a store
// reader or proof of freshness: the owner must use LoadRegistry with epoch and a
// retained minimum control revision. Other durable changes require cold recovery.
// Failed admissions never acquire live sessions here. Existing disconnected
// sessions stay disconnected; surviving handles and transport bindings remain,
// but readiness must be established again through the security lifecycle.
func (r *Registry) ReconcileRegistrationAuthorized(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.publicationBlocked || r.pendingPublication == nil {
		return ErrConflict
	}
	previous, err := r.marshalSnapshot()
	if err != nil {
		return err
	}
	candidate := r.pendingPublication
	pending, err := candidate.MarshalSnapshot()
	if err != nil {
		return err
	}
	switch {
	case bytes.Equal(data, previous):
	case bytes.Equal(data, pending):
		// Only metadata is reconciled. Runtime ownership continues to come from
		// the live registry, including cleanup that ran while the barrier was shut.
		candidate.sessions = maps.Clone(r.sessions)
		for id, service := range candidate.services {
			live := r.services[id]
			service.tunnels = live.tunnels
			for name, version := range service.versions {
				version.sessions = make(map[string]*Session)
				if current := live.versions[name]; current != nil {
					version.sessions = maps.Clone(current.sessions)
					version.primary, version.next = current.primary, current.next
				}
			}
		}
		for path, route := range candidate.routes {
			if current := r.routes[path]; current != nil {
				route.next = current.next
			}
		}
		r.publishRegistration(candidate)
	default:
		return ErrPublicationUnavailable
	}
	for _, session := range r.sessions {
		session.ready = false
		session.readySince = time.Time{}
	}
	r.pendingPublication = nil
	r.publicationBlocked = false
	return nil
}
