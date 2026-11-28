package quictunnel

import (
	"net/netip"
	"sync"
	"time"

	"github.com/solodyagin/outgate/internal/controlstate"
)

// RegistrationLimits bound work after TLS/parse and before grant hashing/SQL.
// Per-minute rates are token buckets with an initial burst equal to the rate.
// Socket/handshake budgets must also be enforced by the listener before TLS.
type RegistrationLimits struct {
	PerServicePerMinute int
	PerIPPerMinute      int
	MaxTrackedIPs       int
	MaxConcurrent       int
}

type registrationBucket struct {
	tokens  float64
	updated time.Time
}

func (b *registrationBucket) take(now time.Time, rate int) bool {
	if now.After(b.updated) {
		b.tokens = min(float64(rate), b.tokens+now.Sub(b.updated).Minutes()*float64(rate))
		b.updated = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type registrationGate struct {
	mu       sync.Mutex
	limits   RegistrationLimits
	ips      map[netip.Addr]*registrationBucket
	order    []netip.Addr
	cursor   int
	services map[string]*registrationBucket
	active   int
	now      func() time.Time
}

func newRegistrationGate(limits RegistrationLimits, services []string) (*registrationGate, error) {
	if limits.PerIPPerMinute < 1 || limits.PerIPPerMinute > 2147483647 || limits.PerServicePerMinute < 1 || limits.PerServicePerMinute > 2147483647 || limits.MaxTrackedIPs < 1 || limits.MaxTrackedIPs > 1000000 || limits.MaxConcurrent < 1 || limits.MaxConcurrent > 1000000 || len(services) == 0 {
		return nil, controlstate.ErrConfig
	}
	g := &registrationGate{limits: limits, ips: make(map[netip.Addr]*registrationBucket), services: make(map[string]*registrationBucket, len(services)), now: time.Now}
	now := g.now()
	for _, id := range services {
		g.services[id] = &registrationBucket{tokens: float64(limits.PerServicePerMinute), updated: now}
	}
	return g, nil
}

func (g *registrationGate) enter(ip netip.Addr) (func(), error) {
	if !ip.IsValid() || ip.Zone() != "" {
		return nil, controlstate.ErrDenied
	}
	ip = ip.Unmap()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active >= g.limits.MaxConcurrent {
		return nil, controlstate.ErrRegistrationQuota
	}
	now := g.now()
	// Bounded maintenance; never evict a live depleted bucket to admit a new IP.
	// An idle minute fully refills any bucket. Capacity exhaustion fails closed
	// even when more idle entries remain for a later maintenance pass.
	for scanned := 0; scanned < 16 && len(g.order) > 0; scanned++ {
		g.cursor %= len(g.order)
		key := g.order[g.cursor]
		if now.Sub(g.ips[key].updated) >= time.Minute {
			delete(g.ips, key)
			g.order[g.cursor] = g.order[len(g.order)-1]
			g.order = g.order[:len(g.order)-1]
		} else {
			g.cursor++
		}
	}
	bucket := g.ips[ip]
	if bucket == nil {
		if len(g.ips) >= g.limits.MaxTrackedIPs {
			return nil, controlstate.ErrUnavailable
		}
		bucket = &registrationBucket{tokens: float64(g.limits.PerIPPerMinute), updated: now}
		g.ips[ip] = bucket
		g.order = append(g.order, ip)
	}
	if !bucket.take(now, g.limits.PerIPPerMinute) {
		return nil, controlstate.ErrRegistrationQuota
	}
	g.active++
	var once sync.Once
	return func() { once.Do(func() { g.mu.Lock(); g.active--; g.mu.Unlock() }) }, nil
}

func (g *registrationGate) service(id string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	bucket := g.services[id]
	if bucket == nil {
		return controlstate.ErrDenied
	}
	if !bucket.take(g.now(), g.limits.PerServicePerMinute) {
		return controlstate.ErrRegistrationQuota
	}
	return nil
}
