package deployment

import (
	"encoding/json"
	"reflect"
	"slices"
	"time"

	v1 "github.com/solodyagin/outgate-sdk/protocol/v1"
	"github.com/solodyagin/outgate/internal/config"
	"github.com/solodyagin/outgate/internal/gateway"
	"github.com/solodyagin/outgate/internal/servicecall"
	"github.com/solodyagin/outgate/internal/transport/quictunnel"
)

// TransportReservations are explicit deployment-owner reservations not guessed
// from unrelated YAML request/body limits. They require platform measurements.
type TransportReservations struct {
	QUICConnectionsPerIP, MaxHandshakes, HandshakesPerIP  int
	MaxConcurrentRegistrations, MaxTrackedRegistrationIPs int
	MaxHTTPRequests                                       int
	ConnectionOverheadBytes                               int64
	StreamReceiveWindow, ConnectionReceiveWindow          uint64
}
type transportInput struct {
	Tunnel struct {
		QUIC struct {
			Enabled        *bool
			Addr           string
			KeepaliveValue string `json:"keepalive_interval"`
			Idle           string `json:"idle_timeout"`
		}
		WSS        struct{ Enabled bool }
		Connect    string `json:"connect_timeout"`
		Handshake  string `json:"tls_handshake_timeout"`
		Register   string `json:"register_timeout"`
		Control    int    `json:"max_control_message_bytes"`
		Inflight   int    `json:"max_inflight_per_tunnel"`
		MaxTunnels int    `json:"max_tunnels"`
	}
	Interservice struct {
		Address string `json:"https_addr"`
	}
	Routing struct {
		Shutdown string `json:"shutdown_timeout"`
	}
	Security struct {
		Rates struct {
			Service int `json:"registrations_per_service_per_minute"`
			IP      int `json:"registrations_per_ip_per_minute"`
		} `json:"rate_limits"`
		Resources struct {
			External     int   `json:"external_connections"`
			PerIP        int   `json:"connections_per_ip"`
			GlobalBytes  int64 `json:"buffer_bytes_global"`
			ServiceBytes int64 `json:"buffer_bytes_per_service"`
			TunnelBytes  int   `json:"buffer_bytes_per_tunnel"`
		} `json:"resource_limits"`
	}
}

// QUICTransportPlan maps the currently supported minor-1 QUIC registration
// profile and local reservations. It never opens sockets or initializes stores.
type QUICTransportPlan struct {
	limits                      quictunnel.RuntimeLimits
	admission                   quictunnel.DurableAdmissionConfig
	tcp                         servicecall.ConnectionLimits
	requests                    int
	quicAddress, serviceAddress string
}

func (*QUICTransportPlan) String() string     { return "outgate QUIC transport plan (redacted)" }
func (p *QUICTransportPlan) GoString() string { return p.String() }

func PlanQUICTransport(doc *config.Document, r TransportReservations) (*QUICTransportPlan, error) {
	if doc == nil || doc.Mode() != "production" || r.MaxHTTPRequests < 1 || r.MaxHTTPRequests > 1000000 {
		return nil, ErrProfile
	}
	var in transportInput
	in.Tunnel.QUIC.Addr = ":7171"
	in.Tunnel.QUIC.KeepaliveValue = "15s"
	in.Tunnel.QUIC.Idle = "45s"
	in.Tunnel.Connect = "5s"
	in.Tunnel.Handshake = "5s"
	in.Tunnel.Register = "10s"
	in.Tunnel.Control = 65536
	in.Tunnel.Inflight = 1000
	in.Tunnel.MaxTunnels = 1000
	in.Routing.Shutdown = "30s"
	in.Security.Rates.Service = 30
	in.Security.Rates.IP = 10
	in.Security.Resources.External = 5000
	in.Security.Resources.PerIP = 50
	in.Security.Resources.GlobalBytes = 536870912
	in.Security.Resources.ServiceBytes = 67108864
	in.Security.Resources.TunnelBytes = 16777216
	values := doc.Values()
	if len(values) == 0 {
		return nil, ErrProfile
	}
	data, err := json.Marshal(values)
	if err != nil {
		return nil, ErrProfile
	}
	defer clear(data)
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, ErrProfile
	}
	if in.Tunnel.QUIC.Enabled != nil && !*in.Tunnel.QUIC.Enabled || in.Tunnel.WSS.Enabled || in.Interservice.Address == "" || in.Tunnel.Control != v1.MaxControlBytes {
		return nil, ErrProfile
	}
	// The current accept-only runtime has fixed heartbeat/shutdown settings and
	// no dialer. Reject other values instead of accepting inert configuration.
	for _, fixed := range []struct {
		value string
		want  time.Duration
	}{{in.Tunnel.QUIC.KeepaliveValue, 15 * time.Second}, {in.Tunnel.QUIC.Idle, 45 * time.Second}, {in.Tunnel.Connect, 5 * time.Second}, {in.Routing.Shutdown, 30 * time.Second}} {
		d, err := time.ParseDuration(fixed.value)
		if err != nil || d != fixed.want {
			return nil, ErrProfile
		}
	}
	handshake, err := time.ParseDuration(in.Tunnel.Handshake)
	if err != nil {
		return nil, ErrProfile
	}
	registration, err := time.ParseDuration(in.Tunnel.Register)
	if err != nil || registration < time.Millisecond || registration > 10*time.Second || registration%time.Millisecond != 0 {
		return nil, ErrProfile
	}
	if in.Security.Resources.External < 1 || in.Security.Resources.PerIP < 1 || in.Security.Resources.PerIP > in.Security.Resources.External || r.MaxConcurrentRegistrations > in.Tunnel.MaxTunnels {
		return nil, ErrProfile
	}
	caps := append(v1.BaselineCapabilities(), "mount_discovery", "credential_generation", v1.QUICQuiescentFenceCapability)
	required := append(v1.BaselineCapabilities(), "credential_generation", v1.QUICQuiescentFenceCapability)
	policy := quictunnel.RegistrationPolicy{
		ProtocolMinor: 1, Capabilities: slices.Clone(caps), RequiredCapabilities: slices.Clone(required),
		Limits:    v1.RegisterAckLimits{MaxControlBytes: in.Tunnel.Control, MaxChunkBytes: v1.MaxChunkBytes, InitialWindowBytes: 65536, MaxHeaderBytes: 32768, MaxRawURIBytes: v1.MaxRawURIBytes, MaxInflight: in.Tunnel.Inflight, BufferBytes: in.Security.Resources.TunnelBytes},
		Timeouts:  v1.RegisterAckTimeouts{RegisterMS: int(registration / time.Millisecond), WriteMS: 10000, CancelAckMS: 10000, StatusIntervalMS: 5000, StatusStaleMS: 15000, DrainMS: 30000},
		Readiness: v1.RegisterAckReadiness{Required: true, IntervalMS: 5000, TimeoutMS: 2000, StaleAfterMS: 15000, FailureThreshold: 3, SuccessThreshold: 2},
	}
	p := &QUICTransportPlan{
		limits:    quictunnel.RuntimeLimits{MaxConnections: in.Tunnel.MaxTunnels, ConnectionsPerIP: r.QUICConnectionsPerIP, MaxHandshakes: r.MaxHandshakes, HandshakesPerIP: r.HandshakesPerIP, BufferBytes: in.Security.Resources.GlobalBytes, BufferBytesPerService: in.Security.Resources.ServiceBytes, ConnectionOverheadBytes: r.ConnectionOverheadBytes, StreamReceiveWindow: r.StreamReceiveWindow, ConnectionReceiveWindow: r.ConnectionReceiveWindow, HandshakeTimeout: handshake},
		admission: quictunnel.DurableAdmissionConfig{Policy: policy, Limits: quictunnel.RegistrationLimits{PerServicePerMinute: in.Security.Rates.Service, PerIPPerMinute: in.Security.Rates.IP, MaxConcurrent: r.MaxConcurrentRegistrations, MaxTrackedIPs: r.MaxTrackedRegistrationIPs}},
		tcp:       servicecall.ConnectionLimits{MaxConnections: in.Security.Resources.External, ConnectionsPerIP: in.Security.Resources.PerIP}, requests: r.MaxHTTPRequests,
		quicAddress: in.Tunnel.QUIC.Addr, serviceAddress: in.Interservice.Address,
	}
	if err := quictunnel.ValidateRuntimeSettings(p.limits, p.admission); err != nil {
		return nil, ErrProfile
	}
	return p, nil
}

// Addresses returns configured socket bind addresses, not client TLS identities.
func (p *QUICTransportPlan) Addresses() (quic, service string, err error) {
	if p == nil || p.requests == 0 {
		return "", "", ErrProfile
	}
	return p.quicAddress, p.serviceAddress, nil
}

func (p *QUICTransportPlan) Bind(base gateway.Config) (gateway.Config, error) {
	if p == nil || p.requests == 0 {
		return gateway.Config{}, ErrProfile
	}
	a := base.Tunnel.Admission
	if !reflect.ValueOf(base.TunnelLimits).IsZero() || !reflect.ValueOf(base.Connections).IsZero() || base.MaxRequests != 0 || !reflect.ValueOf(a.Limits).IsZero() || !reflect.ValueOf(a.Policy).IsZero() || !reflect.ValueOf(a.Bound).IsZero() || !reflect.ValueOf(a.Renewal).IsZero() {
		return gateway.Config{}, ErrProfile
	}
	base.TunnelLimits = p.limits
	base.Connections = p.tcp
	base.MaxRequests = p.requests
	base.Tunnel.Admission.Limits = p.admission.Limits
	policy := p.admission.Policy
	policy.Capabilities = slices.Clone(policy.Capabilities)
	policy.RequiredCapabilities = slices.Clone(policy.RequiredCapabilities)
	base.Tunnel.Admission.Policy = policy
	return base, nil
}
