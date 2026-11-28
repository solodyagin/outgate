package quictunnel

import (
	"context"
	"errors"
	"github.com/solodyagin/outgate-sdk/sessionstate"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/registry"
	"github.com/solodyagin/outgate/internal/resourcebudget"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate-sdk/transport/quicsession"
)

func TestRuntimeDrainReconnectsWhileRetainingStores(t *testing.T) {
	f := runtimeFixtureConfig(t)
	f.reg.Capabilities = append(f.reg.Capabilities, v1.QUICQuiescentFenceCapability)
	f.reg.RequiredCapabilities = append(f.reg.RequiredCapabilities, v1.QUICQuiescentFenceCapability)
	f.config.Admission.Policy.Capabilities = append(f.config.Admission.Policy.Capabilities, v1.QUICQuiescentFenceCapability)
	f.config.Admission.Policy.RequiredCapabilities = append(f.config.Admission.Policy.RequiredCapabilities, v1.QUICQuiescentFenceCapability)
	r, packet, served := startRuntime(t, f)
	_, carrier, _ := runtimeRegister(t, f, packet)
	// Service-side health remains a test assertion. Gateway TLS, grants, ownership,
	// replay warmup and registration publication use the real provisioned stores.
	service, err := quicsession.NewService(carrier, http.NotFoundHandler(), quicsession.Options{SecurityReady: true, ReadinessCheck: func(context.Context) error { return nil }, TickInterval: time.Millisecond})
	must(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = service.Close(ctx)
	})
	bound := runtimeBound(t, r)
	deadline := time.Now().Add(3 * time.Second)
	done := r.BeginDrain(deadline)
	if _, err := r.Session(bound.Handle()); !errors.Is(err, ErrRuntimeClosed) {
		t.Fatal("draining handle resolved", err)
	}
	if r.Ready(t.Context()) == nil {
		t.Fatal("draining runtime ready")
	}
	if other := r.BeginDrain(time.Now().Add(30 * time.Second)); other != done {
		t.Fatal("repeated drain changed owner")
	}
	await(t, done)
	await(t, service.Done())
	must(t, service.Err())
	if !service.ReconnectRequested() {
		t.Fatal("service missed validated reconnect")
	}
	if _, err := r.ControlStore().Revision(t.Context()); err != nil {
		t.Fatal("drain closed shared control store", err)
	}
	if _, err := r.ReplayStore().Health(t.Context()); err != nil {
		t.Fatal("drain closed shared replay store", err)
	}
	if _, err := packet.WriteTo([]byte{0}, packet.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	// Serve remains owned until the composing owner finishes its HTTP users.
	select {
	case err := <-served:
		t.Fatal("drain stopped UDP early", err)
	default:
	}
	must(t, r.Shutdown(t.Context()))
	_ = await(t, served)
}

func TestRuntimeDrainRejectsPreTLSAdmission(t *testing.T) {
	f := runtimeFixtureConfig(t)
	r, err := OpenSQLiteRuntime(t.Context(), f.config, f.limits)
	must(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		must(t, r.Shutdown(ctx))
	})
	await(t, r.BeginDrain(time.Time{}))
	// Existing quota tests exercise Retry/TLS. Here the same post-Retry gate must
	// reject before it allocates a ticket, even without a running listener.
	_, err = r.connectionContext(t.Context(), &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234}, AddrVerified: true})
	if err == nil || r.Stats().Connections != 0 {
		t.Fatal("drain admitted a connection", err)
	}
}

func TestRuntimeDrainForceRetainsBlockedNativeOwnership(t *testing.T) {
	f := runtimeFixtureConfig(t)
	pool, err := resourcebudget.New(resourcebudget.Limits{Connections: 4, ConnectionsPerIP: 4, Bytes: 1 << 30})
	must(t, err)
	f.limits.Shared = pool
	r, packet, _ := startRuntime(t, f)
	conn, _, _ := runtimeRegister(t, f, packet)
	_ = runtimeBound(t, r)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	reg := f.reg
	reg.InstanceID = "blocked-drain-publication"
	result := make(chan error, 1)
	go func() {
		_, err := r.Routes().CommitRegistrationAuthorized(reg, registry.QUIC, func([]byte, uint64) error { close(entered); <-release; return controlstate.ErrUnavailable })
		result <- err
	}()
	await(t, entered)
	done := r.BeginDrain(time.Now().Add(30 * time.Millisecond))
	r.Stop()
	await(t, conn.Context().Done())
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := r.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("released blocked native owner", err)
	}
	if stats := r.Stats(); !stats.Draining || !stats.Stopping || stats.Connections != 1 || stats.ReservedBytes != r.charge {
		t.Fatal("drain released quota before cleanup", stats)
	}
	if stats := pool.Stats(); stats.Connections != 1 || stats.Bytes == 0 {
		t.Fatal("blocked native owner released shared budget", stats)
	}
	if err := r.ControlStore().Close(); !errors.Is(err, controlstate.ErrInstanceInUse) {
		t.Fatal("released durable owner", err)
	}
	once.Do(func() { close(release) })
	if err := await(t, result); !errors.Is(err, controlstate.ErrUnavailable) {
		t.Fatal(err)
	}
	finish, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	must(t, r.Shutdown(finish))
	await(t, done)
	if stats := pool.Stats(); stats != (resourcebudget.Stats{}) {
		t.Fatal("shared budget leaked after native cleanup", stats)
	}
}

func TestRuntimeDrainStartsEverySessionBeforeWaiting(t *testing.T) {
	// Isolate fanout scheduling with two real native/SDK drivers. Their registry
	// admission is synthetic; provisioned SQLite ownership is tested above.
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200); w.(http.Flusher).Flush(); <-release })
	first, firstService, _, firstReg := driverPair(t, handler, func(context.Context) error { return nil })
	second, secondService, _, secondReg := driverPair(t, handler, func(context.Context) error { return nil })
	request := func(path string) *http.Request {
		req, err := http.NewRequestWithContext(t.Context(), "GET", "https://public.example.test"+path, nil)
		must(t, err)
		return req
	}
	one, err := first.RoundTrip(request(firstReg.Paths[0]))
	must(t, err)
	defer one.Body.Close()
	two, err := second.RoundTrip(request(secondReg.Paths[0]))
	must(t, err)
	defer two.Body.Close()
	r := &SQLiteRuntime{ctx: context.Background(), sessions: map[*registry.Session]*BoundSession{first.Handle(): first, second.Handle(): second}, drainDone: make(chan struct{})}
	done := r.BeginDrain(time.Now().Add(3 * time.Second))
	eventually(t, func() bool {
		return first.Snapshot().Phase == sessionstate.Draining && second.Snapshot().Phase == sessionstate.Draining
	})
	if firstService.ReconnectRequested() || secondService.ReconnectRequested() {
		t.Fatal("reconnect before native cleanup")
	}
	once.Do(func() { close(release) })
	_, err = io.ReadAll(one.Body)
	must(t, err)
	must(t, one.Body.Close())
	_, err = io.ReadAll(two.Body)
	must(t, err)
	must(t, two.Body.Close())
	await(t, done)
	await(t, firstService.Done())
	await(t, secondService.Done())
	if !firstService.ReconnectRequested() || !secondService.ReconnectRequested() {
		t.Fatal("session fanout did not reconnect both peers")
	}
}
