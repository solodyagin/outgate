package deployment

import (
	"errors"
	"reflect"
	"testing"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	configuration "github.com/solodyagin/outgate/internal/config"
	"github.com/solodyagin/outgate/internal/gateway"
	"github.com/solodyagin/outgate/internal/transport/quictunnel"
)

func transportReservations() TransportReservations {
	return TransportReservations{QUICConnectionsPerIP: 4, MaxHandshakes: 2, HandshakesPerIP: 2, MaxConcurrentRegistrations: 2, MaxTrackedRegistrationIPs: 10, MaxHTTPRequests: 4, ConnectionOverheadBytes: 65536, StreamReceiveWindow: 32768, ConnectionReceiveWindow: 131072}
}
func TestTransportPlan(t *testing.T) {
	doc, _ := fixture(t)
	p, err := PlanQUICTransport(doc, transportReservations())
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Bind(gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	q, s, err := p.Addresses()
	if err != nil || q != ":7171" || s != ":9443" {
		t.Fatal(q, s, err)
	}
	if c.TunnelLimits.MaxConnections != 1000 || c.TunnelLimits.ConnectionsPerIP != 4 || c.TunnelLimits.HandshakeTimeout != 5*time.Second || c.TunnelLimits.BufferBytes != 536870912 || c.TunnelLimits.BufferBytesPerService != 67108864 || c.Connections.MaxConnections != 5000 || c.Connections.ConnectionsPerIP != 50 || c.MaxRequests != 4 {
		t.Fatal("local limits mapping")
	}
	a := c.Tunnel.Admission
	peer := append(v1.BaselineCapabilities(), "credential_generation", v1.QUICQuiescentFenceCapability)
	if _, err := v1.NegotiateCapabilities(a.Policy.Capabilities, a.Policy.RequiredCapabilities, peer, peer); err != nil {
		t.Fatal("minimal pinned SDK capability profile rejected", err)
	}
	if a.Limits.PerServicePerMinute != 30 || a.Limits.PerIPPerMinute != 10 || a.Limits.MaxConcurrent != 2 || a.Policy.Timeouts.RegisterMS != 10000 || a.Policy.Limits.MaxInflight != 1000 || a.Policy.Limits.BufferBytes != 16777216 || !a.Policy.Readiness.Required {
		t.Fatal("admission mapping")
	}
	if err := quictunnel.ValidateRuntimeSettings(c.TunnelLimits, a); err != nil {
		t.Fatal(err)
	}
	c.Tunnel.Admission.Policy.Capabilities[0] = "changed"
	c.Tunnel.Admission.Policy.RequiredCapabilities[0] = "changed"
	again, err := p.Bind(gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if again.Tunnel.Admission.Policy.Capabilities[0] == "changed" || again.Tunnel.Admission.Policy.RequiredCapabilities[0] == "changed" {
		t.Fatal("mutable policy")
	}
	if _, err := p.Bind(again); !errors.Is(err, ErrProfile) {
		t.Fatal("overrides accepted", err)
	}
}
func TestTransportNondefaults(t *testing.T) {
	_, v := fixture(t)
	tunnel := obj(v, "tunnel")
	tunnel["register_timeout"] = "250ms"
	tunnel["tls_handshake_timeout"] = "3s"
	tunnel["max_inflight_per_tunnel"] = 20
	tunnel["max_tunnels"] = 50
	obj(tunnel, "quic")["addr"] = "127.0.0.1:17171"
	obj(v, "interservice")["https_addr"] = "127.0.0.1:19443"
	rates := obj(obj(v, "security"), "rate_limits")
	rates["registrations_per_service_per_minute"] = 7
	rates["registrations_per_ip_per_minute"] = 3
	resources := obj(obj(v, "security"), "resource_limits")
	resources["external_connections"] = 30
	resources["connections_per_ip"] = 6
	resources["buffer_bytes_per_tunnel"] = 1048576
	p, err := PlanQUICTransport(document(t, v), transportReservations())
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Bind(gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Tunnel.Admission.Policy.Timeouts.RegisterMS != 250 || c.TunnelLimits.HandshakeTimeout != 3*time.Second || c.Tunnel.Admission.Policy.Limits.MaxInflight != 20 || c.Tunnel.Admission.Policy.Limits.BufferBytes != 1048576 || c.Tunnel.Admission.Limits.PerIPPerMinute != 3 || c.Tunnel.Admission.Limits.PerServicePerMinute != 7 || c.TunnelLimits.MaxConnections != 50 || c.Connections.MaxConnections != 30 || c.Connections.ConnectionsPerIP != 6 {
		t.Fatal("nondefault settings lost")
	}
	q, s, err := p.Addresses()
	if err != nil || q != "127.0.0.1:17171" || s != "127.0.0.1:19443" {
		t.Fatal(q, s, err)
	}
}
func TestTransportRejectedSettings(t *testing.T) {
	doc, _ := fixture(t)
	for name, change := range map[string]func(map[string]any){
		"registration_precision": func(v map[string]any) { obj(v, "tunnel")["register_timeout"] = "1.5ms" },
		"registration_zero_ms":   func(v map[string]any) { obj(v, "tunnel")["register_timeout"] = "0.5ms" },
		"registration_max":       func(v map[string]any) { obj(v, "tunnel")["register_timeout"] = "11s" },
		"tls_max": func(v map[string]any) {
			obj(v, "tunnel")["tls_handshake_timeout"] = "6s"
			obj(v, "tunnel")["connect_timeout"] = "4s"
		},
		"tls_min":           func(v map[string]any) { obj(v, "tunnel")["tls_handshake_timeout"] = "1ms" },
		"keepalive":         func(v map[string]any) { obj(obj(v, "tunnel"), "quic")["keepalive_interval"] = "10s" },
		"idle":              func(v map[string]any) { obj(obj(v, "tunnel"), "quic")["idle_timeout"] = "50s" },
		"connect":           func(v map[string]any) { obj(v, "tunnel")["connect_timeout"] = "4s" },
		"drain":             func(v map[string]any) { obj(v, "routing")["shutdown_timeout"] = "20s" },
		"bootstrap_control": func(v map[string]any) { obj(v, "tunnel")["max_control_message_bytes"] = 8192 },
		"inflight":          func(v map[string]any) { obj(v, "tunnel")["max_inflight_per_tunnel"] = 1001 },
		"prepaid_buffer":    func(v map[string]any) { obj(obj(v, "security"), "resource_limits")["buffer_bytes_per_tunnel"] = 100 },
		"buffer_max": func(v map[string]any) {
			obj(obj(v, "security"), "resource_limits")["buffer_bytes_per_tunnel"] = 33554432
		},
		"connections": func(v map[string]any) { obj(obj(v, "security"), "resource_limits")["external_connections"] = 2 },
		"wss":         func(v map[string]any) { obj(obj(v, "tunnel"), "wss")["enabled"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			v := doc.Values()
			change(v)
			if _, err := PlanQUICTransport(document(t, v), transportReservations()); !errors.Is(err, ErrProfile) {
				t.Fatal(err)
			}
		})
	}
	for _, r := range []TransportReservations{{}, func() TransportReservations { r := transportReservations(); r.ConnectionReceiveWindow = 1; return r }(), func() TransportReservations {
		r := transportReservations()
		r.MaxConcurrentRegistrations = 1001
		return r
	}(), func() TransportReservations { r := transportReservations(); r.HandshakesPerIP = 5; return r }(), func() TransportReservations { r := transportReservations(); r.ConnectionOverheadBytes = 0; return r }()} {
		if _, err := PlanQUICTransport(doc, r); !errors.Is(err, ErrProfile) {
			t.Fatal("invalid explicit reservation", err)
		}
	}
	if _, err := PlanQUICTransport(&configuration.Document{}, transportReservations()); !errors.Is(err, ErrProfile) {
		t.Fatal(err)
	}
	if _, _, err := (*QUICTransportPlan)(nil).Addresses(); !errors.Is(err, ErrProfile) {
		t.Fatal(err)
	}
}
func TestTransportDefaults(t *testing.T) {
	_, v := fixture(t)
	for _, key := range []string{"connect_timeout", "tls_handshake_timeout", "register_timeout", "max_control_message_bytes", "max_inflight_per_tunnel", "max_tunnels"} {
		delete(obj(v, "tunnel"), key)
	}
	for _, key := range []string{"enabled", "addr", "keepalive_interval", "idle_timeout"} {
		delete(obj(obj(v, "tunnel"), "quic"), key)
	}
	delete(obj(v, "routing"), "shutdown_timeout")
	for _, key := range []string{"external_connections", "connections_per_ip", "buffer_bytes_global", "buffer_bytes_per_service", "buffer_bytes_per_tunnel"} {
		delete(obj(obj(v, "security"), "resource_limits"), key)
	}
	delete(obj(obj(v, "security"), "rate_limits"), "registrations_per_service_per_minute")
	delete(obj(obj(v, "security"), "rate_limits"), "registrations_per_ip_per_minute")
	p, err := PlanQUICTransport(document(t, v), transportReservations())
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Bind(gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	original, _ := fixture(t)
	expected, err := PlanQUICTransport(original, transportReservations())
	if err != nil {
		t.Fatal(err)
	}
	want, err := expected.Bind(gateway.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatal("defaults drifted")
	}
}
