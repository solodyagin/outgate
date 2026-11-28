// Package resourcebudget provides nonblocking connection and charged-byte admission.
package resourcebudget

import (
	"errors"
	"net/netip"
	"sync"
)

var (
	ErrConfig = errors.New("outgate: invalid shared resource budget")
	ErrFull   = errors.New("outgate: shared resource budget exhausted")
)

type Limits struct {
	Connections, ConnectionsPerIP int
	Bytes                         int64
}
type Stats struct {
	Connections, Peers int
	Bytes              int64
}

// Budget is a fixed local admission pool. Charges are reservations, not measured
// RSS, socket/FD accounting, stream quotas or a guarantee against OS exhaustion.
// All users must share the same pointer; copying a Budget after use is invalid.
type Budget struct {
	mu          sync.Mutex
	limits      Limits
	connections int
	bytes       int64
	peers       map[netip.Addr]int
}

func New(limits Limits) (*Budget, error) {
	if limits.Connections < 1 || limits.Connections > 1000000 || limits.ConnectionsPerIP < 1 || limits.ConnectionsPerIP > limits.Connections || limits.Bytes < 1 {
		return nil, ErrConfig
	}
	return &Budget{limits: limits, peers: map[netip.Addr]int{}}, nil
}

// CanFit checks configuration only; it does not assert current availability.
func (b *Budget) CanFit(bytes int64) bool {
	return b != nil && b.limits.Connections > 0 && bytes > 0 && bytes <= b.limits.Bytes
}

// Acquire atomically reserves one connection and its positive byte charge.
// No waiting queue, goroutine or peer entry is created for a rejected request.
func (b *Budget) Acquire(ip netip.Addr, bytes int64) (*Lease, error) {
	if !b.CanFit(bytes) || !ip.IsValid() || ip.Zone() != "" {
		return nil, ErrConfig
	}
	ip = ip.Unmap()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.connections >= b.limits.Connections || b.peers[ip] >= b.limits.ConnectionsPerIP || b.bytes > b.limits.Bytes-bytes {
		return nil, ErrFull
	}
	b.connections++
	b.bytes += bytes
	b.peers[ip]++
	return &Lease{budget: b, ip: ip, bytes: bytes}, nil
}

// Lease holds a reservation until its actual owner finishes. Release is idempotent.
// There is deliberately no timeout/automatic expiry that could free live usage.
type Lease struct {
	budget *Budget
	ip     netip.Addr
	bytes  int64
	once   sync.Once
}

func (l *Lease) Release() {
	if l == nil || l.budget == nil {
		return
	}
	l.once.Do(func() {
		b := l.budget
		b.mu.Lock()
		defer b.mu.Unlock()
		b.connections--
		b.bytes -= l.bytes
		b.peers[l.ip]--
		if b.peers[l.ip] == 0 {
			delete(b.peers, l.ip)
		}
	})
}
func (b *Budget) Stats() Stats {
	if b == nil {
		return Stats{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return Stats{Connections: b.connections, Peers: len(b.peers), Bytes: b.bytes}
}
