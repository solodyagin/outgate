package registry

import (
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"maps"
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
	_, v, err := r.sessionVersion(session)
	if err != nil {
		return err
	}
	if !session.transportBound || !session.available() || v.retired {
		return ErrConflict
	}
	return nil
}
