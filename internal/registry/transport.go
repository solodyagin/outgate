package registry

import (
	"maps"
	"slices"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

// BindTransport claims one fresh, already authorized registration for its
// transport owner. It neither authorizes nor commits durable state. Exact live
// handles prevent a failed/stale connection from claiming another registration.
func (r *Registry) BindTransport(session *Session, reg v1.Register, transport Transport) (Registration, error) {
	if reg.Validate() != nil {
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
	s, _, err := r.sessionVersion(session)
	if err != nil {
		return Registration{}, err
	}
	i := session.info
	if session.transportBound || session.ready || session.draining || i.ServiceID != reg.ServiceID || i.InstanceID != reg.InstanceID || i.Version != reg.Version || i.Transport != transport || i.PathMode != reg.PathMode || i.RewriteMountHeaders != reg.RewriteMountHeaders || !maps.Equal(paths, session.paths) {
		return Registration{}, ErrConflict
	}
	states := make(map[string]RouteState, len(session.paths))
	for path := range session.paths {
		states[path] = r.state(i.ServiceID, path)
	}
	session.transportBound = true
	return Registration{Session: session, Paths: states, RouteRevision: s.routeRevision}, nil
}

// CanDispatch rechecks a selected handle without selecting another instance or
// permitting a business retry. Per-request route/user authorization is external.
func (r *Registry) CanDispatch(session *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.canDispatch(session)
}

func (r *Registry) canDispatch(session *Session) error {
	if r.publicationBlocked {
		return ErrPublicationUnavailable
	}
	_, v, err := r.sessionVersion(session)
	if err != nil {
		return err
	}
	if !session.transportBound || !session.available() || v.retired {
		return ErrConflict
	}
	return nil
}

// CanDispatchRoute checks the selected target and mount against current state.
// It never advances round robin or changes a selected instance.
func (r *Registry) CanDispatchRoute(decision Decision, rawURI string) error {
	path, err := v1.DecodeRoutePath(rawURI)
	if err != nil {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.canDispatch(decision.Session); err != nil {
		return err
	}
	instance := decision.Session.info
	s := r.services[instance.ServiceID]
	if decision.ServiceID != instance.ServiceID || decision.Version != instance.Version ||
		decision.RouteRevision != s.routeRevision || !decision.Session.serves(decision.Prefix) ||
		r.state(instance.ServiceID, decision.Prefix) != Active {
		return ErrRevisionConflict
	}
	prefix, entry := r.longestRoute(path)
	if entry == nil && r.frontendOn && r.state(r.frontend, "/") == Active {
		for reserved := range r.reserved {
			if v1.MatchesPrefix(reserved, path) {
				return ErrRevisionConflict
			}
		}
		prefix = "/"
	}
	if prefix != decision.Prefix {
		return ErrRevisionConflict
	}
	if s.config.ActivePassive != nil && choosePrimary(s.versions[instance.Version], s.config.ActivePassive, instance.Version, r.now()) != decision.Session {
		return ErrConflict
	}
	if !slices.Contains(weightedVersions(s.rollout), instance.Version) {
		return ErrConflict
	}
	return nil
}
