package quictunnel

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/solodyagin/outgate/internal/registry"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate-sdk/transport/quiccontrol"
	"github.com/solodyagin/outgate-sdk/transport/quichttp"
)

func peerUnregister(t *testing.T, ctx context.Context, c *quiccontrol.Carrier, id v1.U64) {
	t.Helper()
	must(t, c.Send(ctx, v1.Unregister{Type: "unregister", CommandID: id, DeadlineMS: 1000, Code: "shutdown"}))
	message, err := c.Receive(ctx)
	must(t, err)
	ack, ok := message.(v1.UnregisterAck)
	if !ok || ack.CommandID != id {
		t.Fatal("unregister ack mismatch", message)
	}
	must(t, c.Close())
}
func peerFence(t *testing.T, ctx context.Context, app *quichttp.Service, extensions map[string]json.RawMessage) uint64 {
	t.Helper()
	fence, err := v1.DecodeQUICQuiescentFence(extensions)
	must(t, err)
	must(t, app.Quiesce(ctx, fence))
	return fence
}

func TestServiceDrainWaitsForUploadThenUnregisters(t *testing.T) {
	b, c, r, reg, app := boundPairProfile(t, true, nil, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		_, _ = io.Copy(io.Discard, req.Body)
	}))
	makeReady(t, b, c, r, reg, 1)
	reader, writer := io.Pipe()
	defer writer.Close()
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://public.example.test"+reg.Paths[0], reader)
	must(t, err)
	response, err := b.RoundTrip(req)
	must(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	must(t, c.Send(ctx, v1.Drain{Type: "drain", CommandID: 7, DeadlineMS: 3000, Code: "shutdown"}))
	eventually(t, func() bool { return b.Snapshot().Phase == sessionstate.Draining })
	if d := r.Lookup(reg.Paths[0], "", nil); d.Session != nil || d.Status != 503 || d.Upstream {
		t.Fatal("drain did not fence route")
	}
	short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	if _, err := c.Receive(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("ack sent before upload completion", err)
	}
	stop()
	must(t, writer.Close())
	_, err = io.ReadAll(response.Body)
	must(t, err)
	must(t, response.Body.Close())
	message, err := c.Receive(ctx)
	must(t, err)
	ack, ok := message.(v1.DrainAck)
	if !ok || ack.CommandID != 7 {
		t.Fatal(message)
	}
	if fence := peerFence(t, ctx, app, ack.Extensions); fence != 1 {
		t.Fatal("wrong logical watermark", fence)
	}
	peerUnregister(t, ctx, c, 8)
	await(t, b.Done())
	if b.Snapshot().CleanupRequired || b.Snapshot().NativeActive != 0 {
		t.Fatal("graceful cleanup incomplete")
	}
	if d := r.Lookup(reg.Paths[0], "", nil); d.Status != 503 || d.Upstream {
		t.Fatal("unregister released route")
	}
}

func TestGatewayDrainAndCrossedCommands(t *testing.T) {
	for _, crossed := range []bool{false, true} {
		b, c, r, reg, app := boundPairProfile(t, true, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
		makeReady(t, b, c, r, reg, 1)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		result := make(chan error, 1)
		go func() { result <- b.Drain(ctx) }()
		message, err := c.Receive(ctx)
		must(t, err)
		drain, ok := message.(v1.Drain)
		if !ok {
			t.Fatal(message)
		}
		if fence := peerFence(t, ctx, app, drain.Extensions); fence != 0 {
			t.Fatal("empty session has nonzero fence")
		}
		if crossed {
			must(t, c.Send(ctx, v1.Drain{Type: "drain", CommandID: 71, DeadlineMS: 1000, Code: "shutdown"}))
			message, err = c.Receive(ctx)
			must(t, err)
			ack, ok := message.(v1.DrainAck)
			if !ok || ack.CommandID != 71 {
				t.Fatal("crossed drain ack missing", message)
			}
			peerFence(t, ctx, app, ack.Extensions)
		}
		must(t, c.Send(ctx, v1.DrainAck{Type: "drain_ack", CommandID: drain.CommandID}))
		peerUnregister(t, ctx, c, 72)
		must(t, await(t, result))
	}
}

func TestLocalDrainJoinsUnsentPeerDrain(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	b, c, r, reg, app := boundPairProfile(t, true, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200); w.(http.Flusher).Flush(); <-release }))
	makeReady(t, b, c, r, reg, 1)
	req, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test"+reg.Paths[0], nil)
	must(t, err)
	response, err := b.RoundTrip(req)
	must(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- b.Drain(ctx) }()
	eventually(t, func() bool { return b.Snapshot().Phase == sessionstate.Draining })
	must(t, c.Send(ctx, v1.Drain{Type: "drain", CommandID: 9, DeadlineMS: 3000, Code: "shutdown"}))
	eventually(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.peerDrain })
	once.Do(func() { close(release) })
	_, err = io.ReadAll(response.Body)
	must(t, err)
	must(t, response.Body.Close())
	message, err := c.Receive(ctx)
	must(t, err)
	ack, ok := message.(v1.DrainAck)
	if !ok || ack.CommandID != 9 {
		t.Fatal("local intent was not coalesced", message)
	}
	peerFence(t, ctx, app, ack.Extensions)
	peerUnregister(t, ctx, c, 10)
	must(t, await(t, result))
}

func TestDrainDeadlineAndOldCapability(t *testing.T) {
	started := make(chan struct{})
	b, c, r, reg, _ := boundPairProfile(t, true, nil, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-req.Context().Done()
	}))
	makeReady(t, b, c, r, reg, 1)
	req, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test"+reg.Paths[0], nil)
	must(t, err)
	response, err := b.RoundTrip(req)
	must(t, err)
	defer response.Body.Close()
	await(t, started)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := b.Drain(ctx); err == nil {
		t.Fatal("active drain falsely succeeded")
	}
	await(t, b.Done())
	legacy, _, _, _ := boundPair(t, nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err := legacy.Drain(t.Context()); err != ErrControlNotIntegrated {
		t.Fatal("minor 0 silently activated fence", err)
	}
	if legacy.Snapshot().Phase != sessionstate.Registered {
		t.Fatal("unsupported local drain mutated legacy session")
	}
}

func TestTerminalAckWaitIsBounded(t *testing.T) {
	b, c, r, reg, app := boundPairProfile(t, true, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	makeReady(t, b, c, r, reg, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- b.Drain(ctx) }()
	message, err := c.Receive(ctx)
	must(t, err)
	command := message.(v1.Drain)
	peerFence(t, ctx, app, command.Extensions)
	must(t, c.Send(ctx, v1.DrainAck{Type: "drain_ack", CommandID: command.CommandID}))
	must(t, c.Send(ctx, v1.Unregister{Type: "unregister", CommandID: 50, DeadlineMS: 200, Code: "shutdown"}))
	message, err = c.Receive(ctx)
	must(t, err)
	if _, ok := message.(v1.UnregisterAck); !ok {
		t.Fatal(message)
	}
	if _, err = r.RegisterAuthorized(reg, registry.QUIC); err != registry.ErrDuplicate {
		t.Fatal("terminal ack wait released instance/quota early", err)
	}
	// Deliberately violate the service close obligation after consuming the ack.
	if err := await(t, result); err == nil {
		t.Fatal("peer never closed, but graceful drain succeeded")
	}
	await(t, b.Done())
}

func TestServiceCannotForgeGatewayFence(t *testing.T) {
	b, c, r, reg, _ := boundPairProfile(t, true, nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	makeReady(t, b, c, r, reg, 1)
	must(t, c.Send(t.Context(), v1.Drain{Type: "drain", CommandID: 51, DeadlineMS: 1000, Code: "shutdown", Extensions: v1.QUICQuiescentFenceExtensions(0)}))
	await(t, b.Done())
	if !errors.Is(b.Err(), v1.ErrProtocol) {
		t.Fatal("service forged a gateway quiescent fence", b.Err())
	}
}

func TestRevokeAfterRotationAckPreventsReconnect(t *testing.T) {
	b, c, r, reg, app := boundPairProfile(t, true, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	makeReady(t, b, c, r, reg, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	must(t, c.Send(ctx, v1.Drain{Type: "drain", CommandID: 81, DeadlineMS: 2000, Code: "credential_rotation"}))
	message, err := c.Receive(ctx)
	must(t, err)
	ack := message.(v1.DrainAck)
	peerFence(t, ctx, app, ack.Extensions)
	must(t, c.Send(ctx, v1.Unregister{Type: "unregister", CommandID: 82, DeadlineMS: 1000, Code: "credential_rotation"}))
	message, err = c.Receive(ctx)
	must(t, err)
	if _, ok := message.(v1.UnregisterAck); !ok {
		t.Fatal(message)
	}
	b.Revoke()
	await(t, b.Done())
	if !errors.Is(b.Err(), sessionstate.ErrSecurity) || b.Snapshot().Phase != sessionstate.Closed {
		t.Fatal("revoked terminal session retained reconnect intent", b.Err(), b.Snapshot().Phase)
	}
}

func TestLocalCloseAfterAckIsNotGracefulPeerClose(t *testing.T) {
	b, c, r, reg, app := boundPairProfile(t, true, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	makeReady(t, b, c, r, reg, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- b.Drain(ctx) }()
	message, err := c.Receive(ctx)
	must(t, err)
	command := message.(v1.Drain)
	peerFence(t, ctx, app, command.Extensions)
	must(t, c.Send(ctx, v1.DrainAck{Type: "drain_ack", CommandID: command.CommandID}))
	must(t, c.Send(ctx, v1.Unregister{Type: "unregister", CommandID: 91, DeadlineMS: 1000, Code: "shutdown"}))
	message, err = c.Receive(ctx)
	must(t, err)
	if _, ok := message.(v1.UnregisterAck); !ok {
		t.Fatal(message)
	}
	must(t, b.Close(ctx))
	if err := await(t, result); err == nil {
		t.Fatal("local Close claimed graceful peer completion")
	}
}
