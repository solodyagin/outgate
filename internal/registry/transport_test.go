package registry

import "testing"

func TestTransportBindingIsExactAndExclusive(t *testing.T) {
	r := model(t, Config{Development: true, Services: map[string]ServiceConfig{"owner": serviceConfig("/api")}})
	reg := registration("owner", "one", "v1", "/api/orders")
	first := r.connect(reg, QUIC)
	wrong := reg
	wrong.Paths = []string{"/api/other"}
	_, err := r.BindTransport(first.Session, wrong, QUIC)
	wantError(t, err, ErrConflict)
	_, err = r.BindTransport(first.Session, reg, WSS)
	wantError(t, err, ErrConflict)
	bound, err := r.BindTransport(first.Session, reg, QUIC)
	ok(t, err)
	if bound.Paths["/api/orders"] != Active || bound.RouteRevision != first.RouteRevision {
		t.Fatal("binding metadata changed")
	}
	_, err = r.BindTransport(first.Session, reg, QUIC)
	wantError(t, err, ErrConflict)
	wantError(t, r.CanDispatch(first.Session), ErrConflict)
	ok(t, r.SetReady(first.Session, true))
	ok(t, r.CanDispatch(first.Session))
	ok(t, r.Disconnect(first.Session))
	replacement := r.connect(reg, QUIC)
	_, err = r.BindTransport(first.Session, reg, QUIC)
	wantError(t, err, ErrClosedSession)
	_, err = r.BindTransport(replacement.Session, reg, QUIC)
	ok(t, err)
	wantError(t, r.Disconnect(first.Session), ErrClosedSession)
}
