package quictunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quicsession"
	"github.com/solodyagin/outgate/internal/registry"
)

// Unlike the manual control peer tests, both owners run their actual lifecycle
// drivers here. The grant/durable admission callback remains explicitly synthetic.
func driverPair(t *testing.T, handler http.Handler, probe func(context.Context) error) (*BoundSession, *quicsession.Service, *registry.Registry, v1.Register) {
	t.Helper()
	sc, gc := Pair(t, true, v1.QUICALPN)
	reg, ack := Fixtures(t, true)
	reg.ProtocolMinor, ack.ProtocolMinor = 1, 1
	reg.Capabilities = append(reg.Capabilities, v1.QUICQuiescentFenceCapability)
	reg.RequiredCapabilities = append(reg.RequiredCapabilities, v1.QUICQuiescentFenceCapability)
	ack.Capabilities = append(ack.Capabilities, v1.QUICQuiescentFenceCapability)
	ack.RequiredCapabilities = append(ack.RequiredCapabilities, v1.QUICQuiescentFenceCapability)
	ack.ReadyNotBefore = time.Now().Add(-time.Second).Unix()
	ack.Readiness.IntervalMS, ack.Readiness.TimeoutMS, ack.Readiness.StaleAfterMS = 30, 20, 1000
	ack.Readiness.SuccessThreshold, ack.Readiness.FailureThreshold = 1, 1
	ack.Timeouts.StatusIntervalMS, ack.Timeouts.StatusStaleMS = 30, 1000
	routes, err := registry.New(registry.Config{Services: map[string]registry.ServiceConfig{reg.ServiceID: {AllowedPaths: reg.Paths, Rollout: registry.Rollout{Stable: reg.Version}}}})
	must(t, err)
	type result struct {
		s   *BoundSession
		err error
	}
	accepted := make(chan result, 1)
	go func() {
		s, err := AcceptBound(t.Context(), gc, routes, BoundOptions{TickInterval: time.Millisecond}, func(_ context.Context, peer tls.ConnectionState, credential []byte, reg v1.Register) (Binding, error) {
			if len(peer.VerifiedChains) == 0 || string(credential) != "test-only-grant" {
				return Binding{}, errors.New("denied")
			}
			r, err := routes.RegisterAuthorized(reg, registry.QUIC)
			if err != nil {
				return Binding{}, err
			}
			ack.RouteRevision = v1.U64(r.RouteRevision)
			ack.Paths = nil
			for path, state := range r.Paths {
				ack.Paths = append(ack.Paths, v1.RegisterAckPath{Path: path, State: string(state)})
			}
			return Binding{Session: r.Session, Ack: ack, SecurityReady: true}, nil
		})
		accepted <- result{s, err}
	}()
	c, _, err := quiccontrol.Open(t.Context(), sc, quiccontrol.Options{}, []byte("test-only-grant"), reg)
	must(t, err)
	r := await(t, accepted)
	must(t, r.err)
	s, err := quicsession.NewService(c, handler, quicsession.Options{SecurityReady: true, ReadinessCheck: probe, TickInterval: time.Millisecond})
	must(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.Close(ctx)
		_ = r.s.Close(ctx)
	})
	must(t, r.s.EnableDispatch())
	eventually(t, func() bool { return r.s.Snapshot().Phase == sessionstate.Ready })
	must(t, routes.ActivateAuthorized(reg.ServiceID, reg.Paths[0], routes.Revision()))
	return r.s, s, routes, reg
}

func TestServiceDriverDrainInteroperability(t *testing.T) {
	for _, origin := range []string{"gateway", "service", "crossed"} {
		t.Run(origin, func(t *testing.T) {
			var calls atomic.Int32
			g, s, r, reg := driverPair(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }), func(context.Context) error { return nil })
			req, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test"+reg.Paths[0], nil)
			must(t, err)
			response, err := g.RoundTrip(req)
			must(t, err)
			must(t, response.Body.Close())
			if calls.Load() != 1 {
				t.Fatal("handler missing")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			done := make(chan error, 2)
			if origin != "service" {
				go func() { done <- g.Drain(ctx) }()
			}
			if origin != "gateway" {
				go func() { done <- s.Drain(ctx) }()
			}
			must(t, await(t, done))
			if origin == "crossed" {
				must(t, await(t, done))
			}
			await(t, g.Done())
			await(t, s.Done())
			must(t, s.Err())
			if s.ReconnectRequested() || g.Snapshot().CleanupRequired || s.Snapshot().CleanupRequired {
				t.Fatal("incomplete/final cleanup")
			}
			if d := r.Lookup(reg.Paths[0], "", nil); d.Session != nil || d.Status != 503 || d.Upstream {
				t.Fatal("closed route was not retained unavailable", d)
			}
		})
	}
}

func TestServiceDriverDrainsStreamingUpload(t *testing.T) {
	entered := make(chan struct{})
	g, s, _, reg := driverPair(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "streaming\n")
		w.(http.Flusher).Flush()
		close(entered)
		_, _ = io.Copy(io.Discard, r.Body)
	}), func(context.Context) error { return nil })
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://public.example.test"+reg.Paths[0], reader)
	must(t, err)
	response, err := g.RoundTrip(req)
	must(t, err)
	await(t, entered)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Drain(ctx) }()
	eventually(t, func() bool { return g.Snapshot().Phase == sessionstate.Draining })
	select {
	case <-done:
		t.Fatal("upload lost its drain lease")
	default:
	}
	must(t, writer.Close())
	_, err = io.Copy(io.Discard, response.Body)
	must(t, err)
	must(t, response.Body.Close())
	must(t, await(t, done))
	await(t, g.Done())
	await(t, s.Done())
	must(t, s.Err())
}

func TestServiceDriverPublishesReadinessChanges(t *testing.T) {
	var fail atomic.Bool
	g, s, _, reg := driverPair(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), func(context.Context) error {
		if fail.Load() {
			return errors.New("private dependency diagnostic")
		}
		return nil
	})
	fail.Store(true)
	eventually(t, func() bool { return g.Snapshot().Phase == sessionstate.Registered })
	req, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test"+reg.Paths[0], nil)
	must(t, err)
	if _, err = g.RoundTrip(req); !errors.Is(err, sessionstate.ErrState) {
		t.Fatal("unready request admitted", err)
	}
	fail.Store(false)
	eventually(t, func() bool { return g.Snapshot().Phase == sessionstate.Ready })
	response, err := g.RoundTrip(req)
	must(t, err)
	must(t, response.Body.Close())
	must(t, s.SetSecurity(false, time.Time{}))
	eventually(t, func() bool { return g.Snapshot().Phase == sessionstate.Registered })
	s.Revoke()
	await(t, s.Done())
	await(t, g.Done())
	if !errors.Is(s.Err(), sessionstate.ErrSecurity) || s.ReconnectRequested() {
		t.Fatal("security failure did not win")
	}
}
