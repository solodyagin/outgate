package quictunnel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
)

func TestReconnectDriverWaitsForUploadAndCleanup(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	gateway, service, routes, reg := driverPair(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(entered)
		_, _ = io.Copy(io.Discard, req.Body)
	}), func(context.Context) error { return nil })
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	request, err := http.NewRequestWithContext(t.Context(), "POST", "https://public.example.test"+reg.Paths[0], reader)
	must(t, err)
	response, err := gateway.RoundTrip(request)
	must(t, err)
	defer response.Body.Close()
	await(t, entered)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- gateway.Reconnect(ctx) }()
	eventually(t, func() bool { return gateway.Snapshot().Phase == sessionstate.Draining })
	if decision := routes.Lookup(reg.Paths[0], "", nil); decision.Status != 503 || decision.Session != nil || decision.Upstream {
		t.Fatal("reconnect did not exclude route", decision)
	}
	gateway.mu.Lock()
	sent := gateway.localDrainSent
	gateway.mu.Unlock()
	if sent || service.ReconnectRequested() {
		t.Fatal("reconnect before native quiescence/cleanup")
	}
	second, err := http.NewRequestWithContext(t.Context(), "POST", "https://public.example.test"+reg.Paths[0], nil)
	must(t, err)
	if unexpected, err := gateway.RoundTrip(second); err == nil {
		unexpected.Body.Close()
		t.Fatal("new assignment after reconnect")
	}
	must(t, writer.Close())
	_, err = io.ReadAll(response.Body)
	must(t, err)
	must(t, response.Body.Close())
	must(t, await(t, result))
	await(t, service.Done())
	await(t, gateway.Done())
	must(t, service.Err())
	if !service.ReconnectRequested() || gateway.Snapshot().CleanupRequired || service.Snapshot().CleanupRequired || calls.Load() != 1 {
		t.Fatal("missing cleanup/reconnect or business retry", calls.Load(), gateway.Snapshot(), service.Snapshot())
	}
	if decision := routes.Lookup(reg.Paths[0], "", nil); decision.Status != 503 || decision.Session != nil || decision.Upstream {
		t.Fatal("closed route not retained unavailable")
	}
}

func TestReconnectAndDrainKeepFirstLocalIntent(t *testing.T) {
	for _, first := range []string{"reconnect", "drain"} {
		t.Run(first, func(t *testing.T) {
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			b, c, r, reg, app := boundPairProfile(t, true, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200); w.(http.Flusher).Flush(); <-release }))
			makeReady(t, b, c, r, reg, 1)
			req, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test"+reg.Paths[0], nil)
			must(t, err)
			response, err := b.RoundTrip(req)
			must(t, err)
			defer response.Body.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			results := make(chan error, 2)
			initiate := func(callContext context.Context, kind string) {
				if kind == "reconnect" {
					results <- b.Reconnect(callContext)
				} else {
					results <- b.Drain(callContext)
				}
			}
			go initiate(ctx, first)
			eventually(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return len(b.pending) == 1 })
			second := "drain"
			if first == "drain" {
				second = "reconnect"
			}
			shorter, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			go initiate(shorter, second)
			shorterDeadline, _ := shorter.Deadline()
			eventually(t, func() bool { return !b.Snapshot().Deadline.After(shorterDeadline) })
			b.mu.Lock()
			pending := len(b.pending)
			b.mu.Unlock()
			if pending != 1 {
				t.Fatal("repeated intent queued another command", pending)
			}
			// The second call has no additional command to enqueue; release the exchange
			// and let both callers wait on the same terminal handshake.
			once.Do(func() { close(release) })
			_, err = io.ReadAll(response.Body)
			must(t, err)
			must(t, response.Body.Close())
			message, err := c.Receive(ctx)
			must(t, err)
			switch command := message.(type) {
			case v1.Reconnect:
				if first != "reconnect" || command.Code != "server_shutdown" || command.DeadlineMS < 1 || command.DeadlineMS > 30000 {
					t.Fatal("wrong reconnect", command)
				}
				if fence := peerFence(t, ctx, app, command.Extensions); fence != 1 {
					t.Fatal("wrong reconnect watermark", fence)
				}
			case v1.Drain:
				if first != "drain" {
					t.Fatal("changed first intent")
				}
				peerFence(t, ctx, app, command.Extensions)
				must(t, c.Send(ctx, v1.DrainAck{Type: "drain_ack", CommandID: command.CommandID}))
			default:
				t.Fatal("unexpected control", message)
			}
			peerUnregister(t, ctx, c, 91)
			must(t, await(t, results))
			must(t, await(t, results))
		})
	}
}

func TestReconnectJoinsUnsentPeerFinalDrain(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	b, c, r, reg, app := boundPairProfile(t, true, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200); w.(http.Flusher).Flush(); <-release }))
	makeReady(t, b, c, r, reg, 1)
	req, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test"+reg.Paths[0], nil)
	must(t, err)
	response, err := b.RoundTrip(req)
	must(t, err)
	defer response.Body.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- b.Reconnect(ctx) }()
	eventually(t, func() bool { return b.Snapshot().Phase == sessionstate.Draining })
	must(t, c.Send(ctx, v1.Drain{Type: "drain", CommandID: 81, DeadlineMS: 3000, Code: "shutdown"}))
	eventually(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.peerDrain })
	once.Do(func() { close(release) })
	_, err = io.ReadAll(response.Body)
	must(t, err)
	must(t, response.Body.Close())
	message, err := c.Receive(ctx)
	must(t, err)
	ack, ok := message.(v1.DrainAck)
	if !ok || ack.CommandID != 81 {
		t.Fatal("unsent reconnect not coalesced", message)
	}
	if fence := peerFence(t, ctx, app, ack.Extensions); fence != 1 {
		t.Fatal("wrong final-drain watermark", fence)
	}
	peerUnregister(t, ctx, c, 82)
	must(t, await(t, result))
}

func TestReconnectSecurityExpiryPreemptsActiveUpload(t *testing.T) {
	entered := make(chan struct{})
	b, service, _, reg := driverPair(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(entered)
		<-req.Context().Done()
	}), func(context.Context) error { return nil })
	request, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test"+reg.Paths[0], nil)
	must(t, err)
	response, err := b.RoundTrip(request)
	must(t, err)
	defer response.Body.Close()
	await(t, entered)
	must(t, b.SetSecurity(true, time.Now().Add(100*time.Millisecond)))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := b.Reconnect(ctx); !errors.Is(err, sessionstate.ErrSecurity) {
		t.Fatal("reconnect ignored security expiry", err)
	}
	await(t, service.Done())
	if service.ReconnectRequested() {
		t.Fatal("security expiry allowed reconnect hint")
	}
}

func TestReconnectRejectsLegacyAndCanceledIntent(t *testing.T) {
	legacy, _, _, _ := boundPair(t, nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err := legacy.Reconnect(t.Context()); err != ErrControlNotIntegrated {
		t.Fatal("activated legacy fence", err)
	}
	if legacy.Snapshot().Phase != sessionstate.Registered {
		t.Fatal("legacy reconnect mutated state")
	}
	b, _, _, _, _ := boundPairProfile(t, true, nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := b.Reconnect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if b.Snapshot().Phase != sessionstate.Registered {
		t.Fatal("canceled intent mutated state")
	}
}

func TestReconnectDeadlinePreemptsResponse(t *testing.T) {
	b, service, _, reg := driverPair(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-req.Context().Done()
	}), func(context.Context) error { return nil })
	request, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test"+reg.Paths[0], nil)
	must(t, err)
	response, err := b.RoundTrip(request)
	must(t, err)
	defer response.Body.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := b.Reconnect(ctx); !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, sessionstate.ErrTimeout) {
		t.Fatal("reconnect ignored deadline", err)
	}
	await(t, b.Done())
	await(t, service.Done())
	if service.ReconnectRequested() {
		t.Fatal("failed quiescence allowed reconnect hint")
	}
}

func TestReconnectRevocationAfterTerminalAckIsNotGraceful(t *testing.T) {
	b, c, r, reg, app := boundPairProfile(t, true, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	makeReady(t, b, c, r, reg, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- b.Reconnect(ctx) }()
	message, err := c.Receive(ctx)
	must(t, err)
	command, ok := message.(v1.Reconnect)
	if !ok {
		t.Fatal(message)
	}
	peerFence(t, ctx, app, command.Extensions)
	must(t, c.Send(ctx, v1.Unregister{Type: "unregister", CommandID: 99, DeadlineMS: 1000, Code: "shutdown"}))
	message, err = c.Receive(ctx)
	must(t, err)
	if _, ok := message.(v1.UnregisterAck); !ok {
		t.Fatal(message)
	}
	b.Revoke()
	if err := await(t, result); !errors.Is(err, sessionstate.ErrSecurity) {
		t.Fatal("terminal ack bypassed revocation", err)
	}
	if b.Snapshot().CleanupRequired {
		t.Fatal("revoked session not cleaned")
	}
}
