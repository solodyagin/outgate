package quictunnel

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/solodyagin/outgate/internal/controlstate"
)

func TestRegistrationBucketsRefillAndBoundMemory(t *testing.T) {
	now := time.Now()
	g, err := newRegistrationGate(RegistrationLimits{PerIPPerMinute: 2, PerServicePerMinute: 2, MaxTrackedIPs: 1, MaxConcurrent: 2}, []string{"svc"})
	must(t, err)
	g.now = func() time.Time { return now }
	g.services["svc"].updated = now
	ip := netip.MustParseAddr("192.0.2.1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")
	for _, address := range []netip.Addr{ip, mapped} {
		release, err := g.enter(address)
		must(t, err)
		must(t, g.service("svc"))
		release()
		release()
	}
	if _, err := g.enter(ip); !errors.Is(err, controlstate.ErrRegistrationQuota) {
		t.Fatal("IP quota bypass", err)
	}
	if err := g.service("svc"); !errors.Is(err, controlstate.ErrRegistrationQuota) {
		t.Fatal("service quota bypass", err)
	}
	if _, err := g.enter(netip.MustParseAddr("192.0.2.2")); !errors.Is(err, controlstate.ErrUnavailable) {
		t.Fatal("evicted live bucket", err)
	}
	if len(g.ips) != 1 || len(g.order) != 1 || g.active != 0 {
		t.Fatal("unbounded keys or double release")
	}
	now = now.Add(30 * time.Second)
	release, err := g.enter(ip)
	must(t, err)
	release()
	must(t, g.service("svc"))
	if _, err := g.enter(ip); !errors.Is(err, controlstate.ErrRegistrationQuota) {
		t.Fatal("refilled too many tokens", err)
	}
	now = now.Add(-time.Minute)
	if _, err := g.enter(ip); !errors.Is(err, controlstate.ErrRegistrationQuota) {
		t.Fatal("backward clock refilled bucket", err)
	}
	now = now.Add(2 * time.Minute)
	release, err = g.enter(netip.MustParseAddr("192.0.2.2"))
	must(t, err)
	release()
	if len(g.ips) != 1 || g.ips[ip] != nil {
		t.Fatal("idle bucket was not reclaimed")
	}
	if err := g.service("unknown"); !errors.Is(err, controlstate.ErrDenied) || len(g.services) != 1 {
		t.Fatal("untrusted service created state", err)
	}
}

func TestRegistrationConcurrencyHasNoWaitingQueue(t *testing.T) {
	g, err := newRegistrationGate(RegistrationLimits{PerIPPerMinute: 1000, PerServicePerMinute: 1000, MaxTrackedIPs: 1, MaxConcurrent: 3}, []string{"svc"})
	must(t, err)
	ip := netip.MustParseAddr("192.0.2.1")
	var wg sync.WaitGroup
	start := make(chan struct{})
	releaseAll := make(chan struct{})
	var admitted atomic.Int32
	results := make(chan error, 40)
	for range 40 {
		wg.Go(func() {
			<-start
			release, err := g.enter(ip)
			if err == nil {
				admitted.Add(1)
			}
			results <- err
			if err == nil {
				<-releaseAll
				release()
			}
		})
	}
	close(start)
	for range 40 {
		err := await(t, results)
		if err != nil && !errors.Is(err, controlstate.ErrRegistrationQuota) {
			t.Fatal(err)
		}
	}
	if admitted.Load() != 3 || g.active != 3 {
		t.Fatal("concurrency budget bypassed")
	}
	close(releaseAll)
	wg.Wait()
	if g.active != 0 {
		t.Fatal("lost permit")
	}
	release, err := g.enter(ip)
	must(t, err)
	release()
}

func TestRegistrationGateRejectsInvalidBoundsAndAddresses(t *testing.T) {
	for _, limits := range []RegistrationLimits{{}, {PerIPPerMinute: -1, PerServicePerMinute: 1, MaxTrackedIPs: 1, MaxConcurrent: 1}, {PerIPPerMinute: 1, PerServicePerMinute: 1, MaxTrackedIPs: 1000001, MaxConcurrent: 1}} {
		if _, err := newRegistrationGate(limits, []string{"svc"}); !errors.Is(err, controlstate.ErrConfig) {
			t.Fatal("invalid limits", err)
		}
	}
	g, err := newRegistrationGate(RegistrationLimits{PerIPPerMinute: 1, PerServicePerMinute: 1, MaxTrackedIPs: 1, MaxConcurrent: 1}, []string{"svc"})
	must(t, err)
	for _, ip := range []netip.Addr{{}, netip.MustParseAddr("fe80::1%test")} {
		if _, err := g.enter(ip); !errors.Is(err, controlstate.ErrDenied) {
			t.Fatal("invalid peer admitted", err)
		}
	}
}
