package quictunnel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/solodyagin/outgate/internal/controlstate"
)

func TestRuntimeQuotaReservesBeforeTLSAndRetainsAttachedOwnership(t *testing.T) {
	f := runtimeFixtureConfig(t)
	f.limits.MaxHandshakes = 1
	f.limits.HandshakesPerIP = 1
	r, err := OpenSQLiteRuntime(t.Context(), f.config, f.limits)
	must(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	info := &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}, AddrVerified: true}
	owned, err := r.connectionContext(ctx, info)
	must(t, err)
	ticket := owned.Value(runtimeTicketKey{}).(*runtimeTicket)
	if stats := r.Stats(); stats.Connections != 1 || stats.Handshakes != 1 || stats.ReservedBytes != r.charge {
		t.Fatal("handshake allocated without budget", stats)
	}
	if _, err := r.connectionContext(t.Context(), &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1}, AddrVerified: true}); !errors.Is(err, controlstate.ErrRegistrationQuota) {
		t.Fatal("handshake quota bypass", err)
	}
	r.mu.Lock()
	ticket.attached = true
	r.finishHandshakeLocked(ticket)
	r.mu.Unlock()
	must(t, r.bindService(ticket, f.reg.ServiceID))
	cancel()
	// Cancellation cannot release an attached admission/handler owner. Its worker
	// releases the ticket only after actual cleanup, even if network lifetime ended.
	eventually(t, func() bool { return ctx.Err() != nil })
	if r.Stats().Connections != 1 || r.Stats().Handshakes != 0 {
		t.Fatal("network cancellation freed attached resources")
	}
	r.mu.Lock()
	r.releaseLocked(ticket)
	r.releaseLocked(ticket)
	r.mu.Unlock()
	if stats := r.Stats(); stats.Connections != 0 || stats.ReservedBytes != 0 {
		t.Fatal("ticket release leaked/double-debited budget", stats)
	}
	finish, done := context.WithTimeout(t.Context(), time.Second)
	defer done()
	must(t, r.Shutdown(finish))
}

func TestRuntimeQuotaMemoryIPAndServiceLimits(t *testing.T) {
	for _, limit := range []string{"global_memory", "ip", "service_memory"} {
		t.Run(limit, func(t *testing.T) {
			f := runtimeFixtureConfig(t)
			_, charge, err := runtimeTransport(f.limits, f.config.Admission.Policy)
			must(t, err)
			if limit == "global_memory" {
				f.limits.BufferBytes = charge
				f.limits.BufferBytesPerService = charge
			}
			if limit == "ip" {
				f.limits.ConnectionsPerIP = 1
				f.limits.HandshakesPerIP = 1
			}
			if limit == "service_memory" {
				f.limits.BufferBytesPerService = charge
			}
			r, err := OpenSQLiteRuntime(t.Context(), f.config, f.limits)
			must(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			first, err := r.connectionContext(ctx, &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1}, AddrVerified: true})
			must(t, err)
			if limit == "service_memory" {
				must(t, r.bindService(first.Value(runtimeTicketKey{}).(*runtimeTicket), f.reg.ServiceID))
			}
			ip := "192.0.2.2"
			if limit == "ip" {
				ip = "::ffff:192.0.2.1"
			}
			second, err := r.connectionContext(ctx, &quic.ClientInfo{RemoteAddr: &net.UDPAddr{IP: net.ParseIP(ip), Port: 2}, AddrVerified: true})
			if limit == "service_memory" {
				must(t, err)
				if err := r.bindService(second.Value(runtimeTicketKey{}).(*runtimeTicket), f.reg.ServiceID); !errors.Is(err, controlstate.ErrRegistrationQuota) {
					t.Fatal("service budget bypass", err)
				}
				if len(r.services) != 1 {
					t.Fatal("unknown service keys allocated")
				}
			} else if !errors.Is(err, controlstate.ErrRegistrationQuota) {
				t.Fatal("connection budget bypass", err)
			}
			cancel()
			eventually(t, func() bool { return r.Stats().Connections == 0 })
			must(t, r.Shutdown(t.Context()))
		})
	}
}

func TestRuntimeRejectsUnvalidatedAddressWithoutAllocating(t *testing.T) {
	f := runtimeFixtureConfig(t)
	r, err := OpenSQLiteRuntime(t.Context(), f.config, f.limits)
	must(t, err)
	for _, info := range []*quic.ClientInfo{nil, {RemoteAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.1")}}, {AddrVerified: true}} {
		if _, err := r.connectionContext(t.Context(), info); !errors.Is(err, controlstate.ErrDenied) {
			t.Fatal("unvalidated source accepted", err)
		}
	}
	if stats := r.Stats(); stats.Connections != 0 || stats.ReservedBytes != 0 {
		t.Fatal("unvalidated sources consumed state")
	}
	must(t, r.Shutdown(t.Context()))
}
