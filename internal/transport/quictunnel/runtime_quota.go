package quictunnel

import (
	"context"
	"net"
	"net/netip"

	"github.com/quic-go/quic-go"
	"github.com/solodyagin/outgate/internal/controlstate"
)

type runtimeTicketKey struct{}
type runtimePeer struct{ connections, handshakes int }
type runtimeTicket struct {
	runtime                         *SQLiteRuntime
	ip                              netip.Addr
	handshaking, attached, released bool
	service                         string
	conn                            *quic.Conn
}

func runtimeIP(addr net.Addr) (netip.Addr, error) {
	if addr == nil {
		return netip.Addr{}, controlstate.ErrDenied
	}
	host, _, err := net.SplitHostPort(addr.String())
	ip, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || ip.Zone() != "" {
		return netip.Addr{}, controlstate.ErrDenied
	}
	return ip.Unmap(), nil
}

// connectionContext runs after stateless Retry address validation and before
// quic-go allocates the TLS/connection owner. It performs no storage or waiting.
func (r *SQLiteRuntime) connectionContext(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
	if info == nil || !info.AddrVerified {
		return nil, controlstate.ErrDenied
	}
	ip, err := runtimeIP(info.RemoteAddr)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	peer := r.peers[ip]
	if r.stopping || len(r.tickets) >= r.limits.MaxConnections || peer.connections >= r.limits.ConnectionsPerIP || r.handshakes >= r.limits.MaxHandshakes || peer.handshakes >= r.limits.HandshakesPerIP || r.reserved > r.limits.BufferBytes-r.charge {
		r.mu.Unlock()
		return nil, controlstate.ErrRegistrationQuota
	}
	ticket := &runtimeTicket{runtime: r, ip: ip, handshaking: true}
	r.tickets[ticket] = struct{}{}
	peer.connections++
	peer.handshakes++
	r.peers[ip] = peer
	r.handshakes++
	r.reserved += r.charge
	r.mu.Unlock()
	context.AfterFunc(ctx, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !ticket.attached {
			r.releaseLocked(ticket)
		}
	})
	return context.WithValue(ctx, runtimeTicketKey{}, ticket), nil
}

func (r *SQLiteRuntime) attach(conn *quic.Conn) *runtimeTicket {
	ticket, ok := conn.Context().Value(runtimeTicketKey{}).(*runtimeTicket)
	if !ok || ticket.runtime != r {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ticket.released || ticket.attached || r.stopping {
		return nil
	}
	ticket.attached = true
	ticket.conn = conn
	r.finishHandshakeLocked(ticket)
	return ticket
}

func (r *SQLiteRuntime) finishHandshakeLocked(ticket *runtimeTicket) {
	if !ticket.handshaking {
		return
	}
	ticket.handshaking = false
	r.handshakes--
	peer := r.peers[ticket.ip]
	peer.handshakes--
	r.peers[ticket.ip] = peer
}

func (r *SQLiteRuntime) bindService(ticket *runtimeTicket, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	used, known := r.services[id]
	if r.stopping || ticket.released || !known {
		return controlstate.ErrDenied
	}
	if ticket.service != "" || used > r.limits.BufferBytesPerService-r.charge {
		return controlstate.ErrRegistrationQuota
	}
	ticket.service = id
	r.services[id] = used + r.charge
	return nil
}

func (r *SQLiteRuntime) releaseLocked(ticket *runtimeTicket) {
	if ticket.released {
		return
	}
	ticket.released = true
	r.finishHandshakeLocked(ticket)
	peer := r.peers[ticket.ip]
	peer.connections--
	if peer.connections == 0 {
		delete(r.peers, ticket.ip)
	} else {
		r.peers[ticket.ip] = peer
	}
	if ticket.service != "" {
		r.services[ticket.service] -= r.charge
	}
	delete(r.tickets, ticket)
	r.reserved -= r.charge
	r.maybeDrainedLocked()
}
