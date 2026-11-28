package deployment

import (
	"errors"
	"net/netip"
	"testing"

	configuration "github.com/solodyagin/outgate/internal/config"
	"github.com/solodyagin/outgate/internal/gateway"
	"github.com/solodyagin/outgate/internal/resourcebudget"
)

func TestSharedResourceMapping(t *testing.T) {
	if _, err := BindSharedResources(&configuration.Document{}, gateway.Config{}, 100); !errors.Is(err, ErrProfile) {
		t.Fatal("unvalidated zero document accepted", err)
	}
	doc, v := fixture(t)
	config, err := BindSharedResources(doc, gateway.Config{}, 65536)
	if err != nil {
		t.Fatal(err)
	}
	if config.Resources == nil || config.TCPConnectionBytes != 65536 {
		t.Fatal("missing budget binding")
	}
	if !config.Resources.CanFit(536870912) || config.Resources.CanFit(536870913) {
		t.Fatal("global bytes not mapped")
	}
	r := obj(obj(v, "security"), "resource_limits")
	r["external_connections"] = 2
	r["connections_per_ip"] = 1
	c, err := BindSharedResources(document(t, v), gateway.Config{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	one, err := c.Resources.Acquire(ip, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer one.Release()
	if _, err := c.Resources.Acquire(ip, 100); !errors.Is(err, resourcebudget.ErrFull) {
		t.Fatal("per-IP mapping", err)
	}
	two, err := c.Resources.Acquire(netip.MustParseAddr("192.0.2.2"), 100)
	if err != nil {
		t.Fatal(err)
	}
	defer two.Release()
	if _, err := c.Resources.Acquire(netip.MustParseAddr("192.0.2.3"), 100); !errors.Is(err, resourcebudget.ErrFull) {
		t.Fatal("global connection mapping", err)
	}
	for _, charge := range []int64{0, -1, 1<<30 + 1, 536870913} {
		if _, err := BindSharedResources(doc, gateway.Config{}, charge); !errors.Is(err, ErrProfile) {
			t.Fatal(err)
		}
	}
	if _, err := BindSharedResources(doc, config, 100); !errors.Is(err, ErrProfile) {
		t.Fatal("override accepted", err)
	}
	delete(r, "external_connections")
	delete(r, "connections_per_ip")
	delete(r, "buffer_bytes_global")
	defaults, err := BindSharedResources(document(t, v), gateway.Config{}, 100)
	if err != nil || !defaults.Resources.CanFit(536870912) {
		t.Fatal("defaults", err)
	}
}
