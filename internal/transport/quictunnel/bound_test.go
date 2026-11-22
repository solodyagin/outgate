package quictunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quichttp"
	"github.com/solodyagin/outgate/internal/registry"
)

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

func boundPair(t *testing.T, mutate func(*v1.RegisterAck), handler http.Handler) (*BoundSession, *quiccontrol.Carrier, *registry.Registry, v1.Register) {
	t.Helper()
	service, gateway := Pair(t, true, v1.QUICALPN)
	reg, ack := Fixtures(t, true)
	routes, err := registry.New(registry.Config{Services: map[string]registry.ServiceConfig{reg.ServiceID: {AllowedPaths: reg.Paths, Rollout: registry.Rollout{Stable: reg.Version}}}})
	must(t, err)
	type result struct {
		s   *BoundSession
		err error
	}
	accepted := make(chan result, 1)
	go func() {
		s, err := AcceptBound(t.Context(), gateway, routes, BoundOptions{TickInterval: 5 * time.Millisecond}, func(_ context.Context, peer tls.ConnectionState, credential []byte, reg v1.Register) (Binding, error) {
			if len(peer.VerifiedChains) == 0 || string(credential) != "test-only-grant" {
				return Binding{}, errors.New("denied")
			}
			// Synthetic admission callback; no durable production authorization is claimed.
			registered, err := routes.RegisterAuthorized(reg, registry.QUIC)
			if err != nil {
				return Binding{}, err
			}
			ack.RouteRevision = v1.U64(registered.RouteRevision)
			ack.Paths = nil
			for path, state := range registered.Paths {
				ack.Paths = append(ack.Paths, v1.RegisterAckPath{Path: path, State: string(state)})
			}
			if mutate != nil {
				mutate(&ack)
			}
			return Binding{Session: registered.Session, Ack: ack, SecurityReady: true}, nil
		})
		accepted <- result{s, err}
	}()
	control, _, err := quiccontrol.Open(t.Context(), service, quiccontrol.Options{}, []byte("test-only-grant"), reg)
	must(t, err)
	resultValue := await(t, accepted)
	must(t, resultValue.err)
	bound := resultValue.s
	app, err := quichttp.NewService(control, handler)
	must(t, err)
	served := make(chan error, 1)
	go func() { served <- app.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		must(t, bound.Close(ctx))
		_ = app.Close()
		_ = await(t, served)
	})
	return bound, control, routes, reg
}

func makeReady(t *testing.T, b *BoundSession, c *quiccontrol.Carrier, r *registry.Registry, reg v1.Register, sequence v1.U64) {
	t.Helper()
	must(t, b.EnableDispatch())
	must(t, c.Send(t.Context(), v1.InstanceStatus{Type: "instance_status", Sequence: sequence, Ready: true, Code: "ready", ObservedAt: 253402300799}))
	eventually(t, func() bool { return b.Snapshot().Phase == sessionstate.Ready })
	if decision := r.Lookup(reg.Paths[0], "", nil); decision.Session == nil {
		// Production pending routes require explicit activation after readiness.
		must(t, r.ActivateAuthorized(reg.ServiceID, reg.Paths[0], r.Revision()))
	}
}

func TestBoundDoesNotPublishBeforeTransportMapping(t *testing.T) {
	b, c, r, reg := boundPair(t, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	must(t, c.Send(t.Context(), v1.InstanceStatus{Type: "instance_status", Sequence: 1, Ready: true, Code: "ready", ObservedAt: 0}))
	eventually(t, func() bool { return b.Snapshot().Phase == sessionstate.Ready })
	if err := r.CanDispatch(b.Handle()); err != registry.ErrConflict {
		t.Fatal("ready handle exposed before mapping publication")
	}
	req, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test"+reg.Paths[0], nil)
	must(t, err)
	if _, err = b.RoundTrip(req); err != registry.ErrConflict {
		t.Fatal("dispatch enabled implicitly", err)
	}
	must(t, b.EnableDispatch())
	must(t, r.CanDispatch(b.Handle()))
}

func TestBoundReadinessFreshnessRecoveryAndRetainedRoute(t *testing.T) {
	var calls atomic.Int32
	b, c, r, reg := boundPair(t, func(a *v1.RegisterAck) { a.Timeouts.StatusIntervalMS = 20; a.Timeouts.StatusStaleMS = 200 }, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	newRequest := func() *http.Request {
		req, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test"+reg.Paths[0], nil)
		must(t, err)
		return req
	}
	if _, err := b.RoundTrip(newRequest()); !errors.Is(err, sessionstate.ErrState) || calls.Load() != 0 {
		t.Fatal("registered session dispatched before ready", err)
	}
	makeReady(t, b, c, r, reg, 1)
	if r.Lookup(reg.Paths[0], "", nil).Session != b.Handle() {
		t.Fatal("ready session not selected")
	}
	response, err := b.RoundTrip(newRequest())
	must(t, err)
	must(t, response.Body.Close())
	eventually(t, func() bool { return b.Snapshot().NativeActive == 0 })
	eventually(t, func() bool { return b.Snapshot().Phase == sessionstate.Registered })
	if d := r.Lookup(reg.Paths[0], "", nil); d.Session != nil || d.Status != 503 || d.Upstream {
		t.Fatal("stale route fell back or remained ready", d)
	}
	makeReady(t, b, c, r, reg, 2)
	must(t, b.SetSecurity(false, time.Time{}))
	if d := r.Lookup(reg.Paths[0], "", nil); d.Session != nil || d.Status != 503 {
		t.Fatal("security recovery did not exclude session")
	}
	if _, err = b.RoundTrip(newRequest()); !errors.Is(err, sessionstate.ErrState) {
		t.Fatal("security recovery admitted request", err)
	}
	must(t, b.SetSecurity(true, time.Time{}))
	if r.Lookup(reg.Paths[0], "", nil).Session != b.Handle() {
		t.Fatal("fresh ready status not restored after security recovery")
	}
	if _, err = r.RegisterAuthorized(reg, registry.QUIC); err != registry.ErrDuplicate {
		t.Fatal("duplicate instance admitted while active")
	}
	must(t, c.Close())
	await(t, b.Done())
	if d := r.Lookup(reg.Paths[0], "", nil); d.Status != 503 || d.Upstream {
		t.Fatal("disconnect released retained route", d)
	}
	replacement, err := r.RegisterAuthorized(reg, registry.QUIC)
	must(t, err)
	if err = r.SetReady(b.Handle(), true); err != registry.ErrClosedSession {
		t.Fatal("stale handle affected replacement")
	}
	must(t, r.Disconnect(replacement.Session))
}

func TestBoundRevokeCancelsStreamingExchange(t *testing.T) {
	started := make(chan struct{})
	ended := make(chan struct{})
	b, c, r, reg := boundPair(t, nil, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-req.Context().Done()
		close(ended)
	}))
	makeReady(t, b, c, r, reg, 1)
	reader, writer := io.Pipe()
	defer writer.Close()
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://public.example.test"+reg.Paths[0], reader)
	must(t, err)
	response, err := b.RoundTrip(req)
	must(t, err)
	defer response.Body.Close()
	await(t, started)
	if b.Snapshot().NativeActive != 1 {
		t.Fatal("stream not tracked")
	}
	b.Revoke()
	await(t, b.Done())
	await(t, ended)
	if !errors.Is(b.Err(), sessionstate.ErrSecurity) || b.Snapshot().NativeActive != 0 || b.Snapshot().CleanupRequired {
		t.Fatal("revoke skipped lifecycle cleanup", b.Err())
	}
	writeResult := make(chan error, 1)
	go func() { _, err := writer.Write([]byte("after revoke")); writeResult <- err }()
	if await(t, writeResult) == nil {
		t.Fatal("upload not canceled")
	}
}

func TestBoundHalfCloseHoldsLeaseAndSecurityDeadline(t *testing.T) {
	finished := make(chan error, 1)
	b, c, r, reg := boundPair(t, nil, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		stream, err := w.(http3.HTTPStreamer).HTTPStream()
		if err == nil {
			err = stream.Close()
		}
		if err == nil {
			_, err = io.Copy(io.Discard, req.Body)
		}
		finished <- err
	}))
	makeReady(t, b, c, r, reg, 1)
	reader, writer := io.Pipe()
	defer writer.Close()
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://public.example.test"+reg.Paths[0], reader)
	must(t, err)
	response, err := b.RoundTrip(req)
	must(t, err)
	_, err = io.ReadAll(response.Body)
	must(t, err)
	if b.Snapshot().NativeActive != 1 {
		t.Fatal("response EOF released active upload")
	}
	_, err = writer.Write([]byte("upload after FIN"))
	must(t, err)
	must(t, writer.Close())
	must(t, await(t, finished))
	must(t, response.Body.Close())
	eventually(t, func() bool { return b.Snapshot().NativeActive == 0 })
	must(t, b.SetSecurity(true, time.Now().Add(50*time.Millisecond)))
	await(t, b.Done())
	if !errors.Is(b.Err(), sessionstate.ErrSecurity) {
		t.Fatal("security deadline not enforced without traffic", b.Err())
	}
}

func TestBoundRejectsDuplicateStatusAndUnintegratedCommands(t *testing.T) {
	for _, command := range []bool{false, true} {
		b, c, r, reg := boundPair(t, nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		makeReady(t, b, c, r, reg, 1)
		var message any = v1.InstanceStatus{Type: "instance_status", Sequence: 1, Ready: true, Code: "ready", ObservedAt: 0}
		if command {
			message = v1.Drain{Type: "drain", CommandID: 7, DeadlineMS: 1000, Code: "shutdown"}
		}
		must(t, c.Send(t.Context(), message))
		await(t, b.Done())
		if command && !errors.Is(b.Err(), ErrControlNotIntegrated) {
			t.Fatal("fake graceful fence issued")
		}
		if !command && !errors.Is(b.Err(), v1.ErrProtocol) {
			t.Fatal("duplicate sequence accepted", b.Err())
		}
	}
}

func TestBoundReadyNotBeforeAndCredentialExpiry(t *testing.T) {
	barrier := time.Now().Truncate(time.Second).Add(2 * time.Second).Unix()
	b, c, r, reg := boundPair(t, func(a *v1.RegisterAck) { a.ReadyNotBefore = barrier; a.CredentialExpiresAt = &barrier }, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.Copy(w, strings.NewReader("must not run")) }))
	must(t, c.Send(t.Context(), v1.InstanceStatus{Type: "instance_status", Sequence: 1, Ready: true, Code: "ready", ObservedAt: barrier + 1000}))
	eventually(t, func() bool { return b.Snapshot().Sequence == 1 })
	if b.Snapshot().Phase != sessionstate.Registered {
		t.Fatal("future observed_at bypassed recovery barrier")
	}
	await(t, b.Done())
	if !errors.Is(b.Err(), sessionstate.ErrSecurity) || r.Lookup(reg.Paths[0], "", nil).Session != nil {
		t.Fatal("credential expiry ignored")
	}
}

func TestBoundFailureDoesNotStealExistingTransport(t *testing.T) {
	b, c, r, reg := boundPair(t, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	makeReady(t, b, c, r, reg, 1)
	service, gateway := Pair(t, true, v1.QUICALPN)
	_, ack := Fixtures(t, true)
	result := make(chan error, 1)
	go func() {
		bound, err := AcceptBound(t.Context(), gateway, r, BoundOptions{}, func(context.Context, tls.ConnectionState, []byte, v1.Register) (Binding, error) {
			return Binding{Session: b.Handle(), Ack: ack, SecurityReady: true}, nil
		})
		if bound != nil {
			result <- errors.New("existing transport stolen")
			return
		}
		result <- err
	}()
	if _, _, err := quiccontrol.Open(t.Context(), service, quiccontrol.Options{}, []byte("test-only-grant"), reg); err == nil {
		t.Fatal("duplicate binding accepted")
	}
	if await(t, result) == nil {
		t.Fatal("duplicate binding did not fail")
	}
	must(t, r.CanDispatch(b.Handle()))
}

func TestBoundAckFailureCleansOwnedRegistration(t *testing.T) {
	service, gateway := Pair(t, true, v1.QUICALPN)
	reg, ack := Fixtures(t, true)
	r, err := registry.New(registry.Config{Services: map[string]registry.ServiceConfig{reg.ServiceID: {AllowedPaths: reg.Paths, Rollout: registry.Rollout{Stable: reg.Version}}}})
	must(t, err)
	result := make(chan error, 1)
	go func() {
		_, err := AcceptBound(t.Context(), gateway, r, BoundOptions{}, func(_ context.Context, _ tls.ConnectionState, _ []byte, reg v1.Register) (Binding, error) {
			registered, err := r.RegisterAuthorized(reg, registry.QUIC)
			if err != nil {
				return Binding{}, err
			}
			ack.RouteRevision = v1.U64(registered.RouteRevision + 1) // mismatch with actual registry snapshot
			return Binding{Session: registered.Session, Ack: ack, SecurityReady: true}, nil
		})
		result <- err
	}()
	if _, _, err = quiccontrol.Open(t.Context(), service, quiccontrol.Options{}, []byte("test-only-grant"), reg); err == nil {
		t.Fatal("invalid ack accepted")
	}
	if await(t, result) == nil {
		t.Fatal("registry/ack mismatch accepted")
	}
	replacement, err := r.RegisterAuthorized(reg, registry.QUIC)
	must(t, err)
	must(t, r.Disconnect(replacement.Session))
}

type blockedCloseBody struct {
	released, closing chan struct{}
	once              sync.Once
}

func (b *blockedCloseBody) Read([]byte) (int, error) { <-b.released; return 0, io.EOF }
func (b *blockedCloseBody) Close() error {
	b.once.Do(func() { close(b.closing) })
	<-b.released
	return nil
}

func TestBoundCleanupRetainsDuplicateIDUntilUploadReleased(t *testing.T) {
	b, c, r, reg := boundPair(t, nil, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-req.Context().Done()
	}))
	makeReady(t, b, c, r, reg, 1)
	body := &blockedCloseBody{released: make(chan struct{}), closing: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(body.released) }) }
	defer release()
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://public.example.test"+reg.Paths[0], body)
	must(t, err)
	response, err := b.RoundTrip(req)
	must(t, err)
	defer response.Body.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err = b.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("uncooperative upload cleanup was not bounded", err)
	}
	await(t, body.closing)
	if _, err = r.RegisterAuthorized(reg, registry.QUIC); err != registry.ErrDuplicate {
		t.Fatal("replacement admitted before cleanup", err)
	}
	select {
	case <-b.Done():
		t.Fatal("cleanup claimed completion while upload blocked")
	default:
	}
	release()
	await(t, b.Done())
	replacement, err := r.RegisterAuthorized(reg, registry.QUIC)
	must(t, err)
	must(t, r.Disconnect(replacement.Session))
}
