package resourcebudget

import (
	"errors"
	"math"
	"net/netip"
	"sync"
	"testing"
)

func TestLimitsAndRelease(t *testing.T) {
	b, err := New(Limits{Connections: 3, ConnectionsPerIP: 1, Bytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	one, err := b.Acquire(ip, 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Acquire(netip.MustParseAddr("::ffff:192.0.2.1"), 1); !errors.Is(err, ErrFull) {
		t.Fatal("mapped IP bypass", err)
	}
	two, err := b.Acquire(netip.MustParseAddr("192.0.2.2"), 6)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Acquire(netip.MustParseAddr("192.0.2.3"), 1); !errors.Is(err, ErrFull) {
		t.Fatal("byte bypass", err)
	}
	if s := b.Stats(); s.Connections != 2 || s.Peers != 2 || s.Bytes != 10 {
		t.Fatal(s)
	}
	one.Release()
	one.Release()
	two.Release()
	if s := b.Stats(); s != (Stats{}) {
		t.Fatal(s)
	}
}
func TestBoundaryAndInvalid(t *testing.T) {
	for _, l := range []Limits{{}, {Connections: 1, ConnectionsPerIP: 2, Bytes: 1}, {Connections: 1000001, ConnectionsPerIP: 1, Bytes: 1}} {
		if _, err := New(l); !errors.Is(err, ErrConfig) {
			t.Fatal(err)
		}
	}
	b, err := New(Limits{Connections: 1, ConnectionsPerIP: 1, Bytes: math.MaxInt64})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("2001:db8::1")
	for _, bytes := range []int64{0, -1} {
		if _, err := b.Acquire(ip, bytes); !errors.Is(err, ErrConfig) {
			t.Fatal(err)
		}
	}
	for _, ip := range []netip.Addr{{}, netip.MustParseAddr("fe80::1%zone")} {
		if _, err := b.Acquire(ip, 1); !errors.Is(err, ErrConfig) {
			t.Fatal(err)
		}
	}
	lease, err := b.Acquire(ip, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Acquire(netip.MustParseAddr("2001:db8::2"), 1); !errors.Is(err, ErrFull) {
		t.Fatal("overflow/count bypass", err)
	}
	lease.Release()
	var zero Lease
	zero.Release()
	(*Lease)(nil).Release()
	var zeroBudget Budget
	if _, err := zeroBudget.Acquire(ip, 1); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
	if _, err := (*Budget)(nil).Acquire(ip, 1); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
}
func TestConcurrentAdmission(t *testing.T) {
	b, err := New(Limits{Connections: 5, ConnectionsPerIP: 5, Bytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 100 {
				lease, err := b.Acquire(netip.MustParseAddr("192.0.2.1"), 2)
				if err == nil {
					if s := b.Stats(); s.Connections > 5 || s.Bytes > 10 {
						t.Error(s)
					}
					lease.Release()
				} else if !errors.Is(err, ErrFull) {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	if s := b.Stats(); s != (Stats{}) {
		t.Fatal(s)
	}
}
