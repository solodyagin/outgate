package quictunnel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/solodyagin/outgate/internal/controlstate"
	"github.com/solodyagin/outgate/internal/resourcebudget"
	"github.com/solodyagin/outgate/internal/servicecall"
)

func TestSharedBudgetAcrossTCPAndQUIC(t *testing.T) {
	for _, kind := range []string{"connections", "bytes", "ip"} {
		t.Run(kind, func(t *testing.T) {
			f := runtimeFixtureConfig(t)
			_, charge, err := runtimeTransport(f.limits, f.config.Admission.Policy)
			must(t, err)
			const tcpBytes = 1024
			limits := resourcebudget.Limits{Connections: 3, ConnectionsPerIP: 3, Bytes: charge * 3}
			switch kind {
			case "connections":
				limits.Connections = 1
				limits.ConnectionsPerIP = 1
			case "bytes":
				limits.Bytes = charge + tcpBytes - 1
			case "ip":
				limits.ConnectionsPerIP = 1
			}
			pool, err := resourcebudget.New(limits)
			must(t, err)
			f.limits.Shared = pool
			r, err := OpenSQLiteRuntime(t.Context(), f.config, f.limits)
			must(t, err)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				must(t, r.Shutdown(ctx))
			})
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			must(t, err)
			limited, err := servicecall.LimitListener(listener, servicecall.ConnectionLimits{MaxConnections: 3, ConnectionsPerIP: 3, Shared: pool, ConnectionBytes: tcpBytes})
			must(t, err)
			defer limited.Close()
			client, err := net.Dial("tcp", listener.Addr().String())
			must(t, err)
			defer client.Close()
			accepted, err := limited.Accept()
			must(t, err)
			defer accepted.Close()
			info := &quic.ClientInfo{AddrVerified: true, RemoteAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}}
			if _, err := r.connectionContext(t.Context(), info); !errors.Is(err, controlstate.ErrRegistrationQuota) {
				t.Fatal("TCP usage did not limit QUIC", err)
			}
			if r.Stats().Connections != 0 || pool.Stats().Connections != 1 || pool.Stats().Bytes != tcpBytes {
				t.Fatal("rejected QUIC allocated resources", pool.Stats())
			}
			must(t, accepted.Close())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			owned, err := r.connectionContext(ctx, info)
			must(t, err)
			ticket := owned.Value(runtimeTicketKey{}).(*runtimeTicket)
			r.mu.Lock()
			ticket.attached = true
			r.finishHandshakeLocked(ticket)
			r.mu.Unlock()
			cancel()
			if pool.Stats().Connections != 1 || pool.Stats().Bytes != charge {
				t.Fatal("attached owner lost shared reservation", pool.Stats())
			}
			done := make(chan error, 1)
			go func() {
				conn, err := limited.Accept()
				if err == nil {
					_ = conn.Close()
				}
				done <- err
			}()
			excess, err := net.Dial("tcp", listener.Addr().String())
			must(t, err)
			defer excess.Close()
			must(t, excess.SetReadDeadline(time.Now().Add(2*time.Second)))
			var b [1]byte
			if _, err := excess.Read(b[:]); err == nil {
				t.Fatal("QUIC usage did not limit TCP")
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("excess TCP not closed before TLS", err)
			}
			must(t, limited.Close())
			if err := await(t, done); err == nil {
				t.Fatal("excess TCP accepted")
			}
			r.mu.Lock()
			r.releaseLocked(ticket)
			r.releaseLocked(ticket)
			r.mu.Unlock()
			if s := pool.Stats(); s != (resourcebudget.Stats{}) {
				t.Fatal("shared reservation leaked", s)
			}
		})
	}
}
func TestUnattachedQUICCancellationReleasesSharedBudget(t *testing.T) {
	f := runtimeFixtureConfig(t)
	pool, err := resourcebudget.New(resourcebudget.Limits{Connections: 2, ConnectionsPerIP: 2, Bytes: 1 << 30})
	must(t, err)
	f.limits.Shared = pool
	r, err := OpenSQLiteRuntime(t.Context(), f.config, f.limits)
	must(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	_, err = r.connectionContext(ctx, &quic.ClientInfo{AddrVerified: true, RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}})
	must(t, err)
	cancel()
	eventually(t, func() bool { return pool.Stats() == (resourcebudget.Stats{}) })
	must(t, r.Shutdown(t.Context()))
}

func TestSharedBudgetMustFitNativeCharge(t *testing.T) {
	f := runtimeFixtureConfig(t)
	pool, err := resourcebudget.New(resourcebudget.Limits{Connections: 1, ConnectionsPerIP: 1, Bytes: 1})
	must(t, err)
	f.limits.Shared = pool
	if _, _, err := runtimeTransport(f.limits, f.config.Admission.Policy); !errors.Is(err, controlstate.ErrConfig) {
		t.Fatal("undersized shared pool accepted", err)
	}
}
