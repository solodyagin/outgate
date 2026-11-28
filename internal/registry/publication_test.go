package registry

import (
	"bytes"
	"errors"
	"net/http"
	"sync"
	"testing"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
)

func livePublicationRegistry(t *testing.T) (*testRegistry, v1.Register, *Session) {
	t.Helper()
	r := model(t, Config{Development: true, Services: map[string]ServiceConfig{"svc": serviceConfig("/api")}})
	reg := registration("svc", "one", "v1", "/api")
	result := r.connect(reg, QUIC)
	_, err := r.BindTransport(result.Session, reg, QUIC)
	ok(t, err)
	ok(t, r.SetReady(result.Session, true))
	return r, reg, result.Session
}

func TestRegistrationPublicationKeepsLiveHandles(t *testing.T) {
	r, reg, first := livePublicationRegistry(t)
	before, err := r.MarshalSnapshot()
	ok(t, err)
	reg.InstanceID = "two"
	var stored []byte
	result, err := r.CommitRegistrationAuthorized(reg, QUIC, func(data []byte, previous uint64) error {
		if previous != 1 || r.revision != 1 || r.sessions["two"] != nil {
			t.Fatal("candidate became visible before commit")
		}
		current, err := r.marshalSnapshot()
		ok(t, err)
		if !bytes.Equal(before, current) {
			t.Fatal("candidate mutated live metadata")
		}
		stored = bytes.Clone(data)
		return nil
	})
	ok(t, err)
	if result.Session == nil || result.Session == first || result.Session.ready || r.Revision() != 2 {
		t.Fatal("invalid published session")
	}
	r.selected("/api/x", "", first)
	ok(t, r.CanDispatch(first))
	// Publication must retain readiness and exact bindings, not recover from a
	// snapshot or mint replacement handles for already connected transports.
	if !first.transportBound || first.readySince.IsZero() {
		t.Fatal("runtime state reset")
	}
	actual, err := r.MarshalSnapshot()
	ok(t, err)
	if !bytes.Equal(stored, actual) {
		t.Fatal("published different candidate")
	}
	_, err = r.BindTransport(result.Session, reg, QUIC)
	ok(t, err)
	ok(t, r.SetReady(result.Session, true))
	ok(t, r.Disconnect(first))
	r.selected("/api/x", "", result.Session)
}

func assertPublicationBarrier(t *testing.T, r *Registry, session *Session, reg v1.Register) {
	t.Helper()
	if got := r.Lookup("/app", "", nil); got.Status != http.StatusServiceUnavailable || got.Upstream {
		t.Fatal("barrier permitted fallback", got)
	}
	wantError(t, r.CanDispatch(session), ErrPublicationUnavailable)
	wantError(t, r.CanDispatchRoute(Decision{Session: session}, "/api"), ErrPublicationUnavailable)
	wantError(t, r.SetReady(session, true), ErrPublicationUnavailable)
	_, _, err := r.Discovery("svc")
	wantError(t, err, ErrPublicationUnavailable)
	_, err = r.BindTransport(session, reg, QUIC)
	wantError(t, err, ErrPublicationUnavailable)
	_, err = r.RegisterAuthorized(reg, QUIC)
	wantError(t, err, ErrPublicationUnavailable)
	_, err = r.CommitRegistrationAuthorized(reg, QUIC, func([]byte, uint64) error { t.Fatal("barrier allowed persist"); return nil })
	wantError(t, err, ErrPublicationUnavailable)
	wantError(t, r.RetireAuthorized("svc", "/api", r.Revision()), ErrPublicationUnavailable)
	versions, err := r.Versions("svc")
	ok(t, err)
	for _, version := range versions {
		if version.Instances != 0 {
			t.Fatal("barrier advertised ready instances")
		}
	}
}

func TestRegistrationPublicationFailureAndVerifiedResync(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "lost_commit_result"}[committed], func(t *testing.T) {
			r, reg, first := livePublicationRegistry(t)
			before, err := r.MarshalSnapshot()
			ok(t, err)
			failure := errors.New("uncertain commit")
			var pending []byte
			reg.InstanceID, reg.Version, reg.Paths = "two", "candidate", []string{"/api/new"}
			result, err := r.CommitRegistrationAuthorized(reg, QUIC, func(data []byte, _ uint64) error { pending = bytes.Clone(data); return failure })
			wantError(t, err, failure)
			if result.Session != nil || r.Revision() != 1 || r.sessions["two"] != nil || r.services["svc"].versions["candidate"] != nil || r.routes["/api/new"] != nil {
				t.Fatal("failed candidate leaked")
			}
			assertPublicationBarrier(t, r.Registry, first, reg)
			wantError(t, r.ReconcileRegistrationAuthorized([]byte("unverified")), ErrPublicationUnavailable)
			assertPublicationBarrier(t, r.Registry, first, reg)
			durable := before
			if committed {
				durable = pending
			}
			ok(t, r.ReconcileRegistrationAuthorized(durable))
			if r.sessions["one"] != first || r.sessions["two"] != nil || first.ready || !first.transportBound {
				t.Fatal("resync replaced/resurrected handles or readiness")
			}
			actual, err := r.MarshalSnapshot()
			ok(t, err)
			if !bytes.Equal(durable, actual) {
				t.Fatal("resync changed durable metadata")
			}
			ok(t, r.SetReady(first, true))
			ok(t, r.CanDispatch(first))
			r.selected("/api/x", "", first)
			// A failed admission is not acknowledged/resurrected by resync. Only a
			// new explicit admission can create its session.
			result, err = r.CommitRegistrationAuthorized(reg, QUIC, func([]byte, uint64) error { return nil })
			ok(t, err)
			if result.Session == nil || result.Session.ready {
				t.Fatal("reconnect was not fresh")
			}
		})
	}
}

func TestRegistrationResyncPreservesCleanup(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		t.Run(map[bool]string{false: "drain", true: "disconnect"}[disconnect], func(t *testing.T) {
			r, reg, first := livePublicationRegistry(t)
			reg.InstanceID = "two"
			var data []byte
			_, err := r.CommitRegistrationAuthorized(reg, QUIC, func(p []byte, _ uint64) error { data = bytes.Clone(p); return errors.New("lost result") })
			if err == nil {
				t.Fatal("expected failure")
			}
			ok(t, r.SetReady(first, false))
			if disconnect {
				ok(t, r.Disconnect(first))
			} else {
				ok(t, r.Drain(first))
			}
			ok(t, r.ReconcileRegistrationAuthorized(data))
			if len(r.sessions) != map[bool]int{false: 1, true: 0}[disconnect] || r.services["svc"].tunnels != len(r.sessions) {
				t.Fatal("resurrected cleaned-up session")
			}
			if disconnect {
				wantError(t, r.SetReady(first, true), ErrClosedSession)
			} else {
				wantError(t, r.SetReady(first, true), ErrConflict)
			}
			r.status("/api/x", "", http.StatusServiceUnavailable)
		})
	}
}

func TestRegistrationPublicationPanicClosesBarrier(t *testing.T) {
	r, reg, first := livePublicationRegistry(t)
	before, err := r.MarshalSnapshot()
	ok(t, err)
	reg.InstanceID = "two"
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("missing panic")
			}
		}()
		_, _ = r.CommitRegistrationAuthorized(reg, QUIC, func([]byte, uint64) error { panic("storage panic") })
	}()
	assertPublicationBarrier(t, r.Registry, first, reg)
	ok(t, r.ReconcileRegistrationAuthorized(before))
}

func TestConcurrentDurableRegistrations(t *testing.T) {
	r, reg, first := livePublicationRegistry(t)
	var wg sync.WaitGroup
	failures := make(chan error, 12)
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"} {
		wg.Go(func() {
			reg := reg
			reg.InstanceID = id
			_, err := r.CommitRegistrationAuthorized(reg, QUIC, func(data []byte, previous uint64) error {
				restored, err := RestoreSnapshot(Config{Development: true, Services: map[string]ServiceConfig{"svc": serviceConfig("/api")}}, data)
				if err != nil {
					return err
				}
				if restored.Revision() != previous+1 {
					return ErrRevisionConflict
				}
				return nil
			})
			if err != nil {
				failures <- err
			}
		})
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if r.Revision() != 13 || len(r.sessions) != 13 {
		t.Fatal("lost serialized admission")
	}
	ok(t, r.CanDispatch(first))
}

func TestInvalidRegistrationDoesNotClosePublication(t *testing.T) {
	r, reg, first := livePublicationRegistry(t)
	reg.Paths = []string{"/forbidden"}
	_, err := r.CommitRegistrationAuthorized(reg, QUIC, func([]byte, uint64) error { t.Fatal("persisted invalid registration"); return nil })
	wantError(t, err, ErrDuplicate)
	reg.InstanceID = "two"
	_, err = r.CommitRegistrationAuthorized(reg, QUIC, func([]byte, uint64) error { t.Fatal("persisted invalid registration"); return nil })
	wantError(t, err, ErrPathForbidden)
	ok(t, r.CanDispatch(first))
}

func TestPublicationPreservesActivePassivePrimary(t *testing.T) {
	cfg := serviceConfig("/api")
	cfg.ActivePassive = &ActivePassive{Orders: map[string][]string{"v1": {"one", "two"}}}
	r := model(t, Config{Development: true, Services: map[string]ServiceConfig{"svc": cfg}})
	reg := registration("svc", "one", "v1", "/api")
	first := r.connect(reg, QUIC).Session
	_, err := r.BindTransport(first, reg, QUIC)
	ok(t, err)
	ok(t, r.SetReady(first, true))
	r.selected("/api/x", "", first)
	since := first.readySince
	primary := r.services["svc"].versions["v1"].primary
	reg.InstanceID = "two"
	_, err = r.CommitRegistrationAuthorized(reg, QUIC, func([]byte, uint64) error { return nil })
	ok(t, err)
	if r.services["svc"].versions["v1"].primary != primary || primary != first || !first.readySince.Equal(since) {
		t.Fatal("publication reset active-passive runtime")
	}
	r.selected("/api/x", "", first)
}
