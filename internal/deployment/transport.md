# QUIC transport and admission settings

`PlanQUICTransport(document, reservations)` is an IO-free component projection
for production QUIC-only shared ingress. It binds local TCP/QUIC limits, admission
limits and a supported minor-1 registration policy into a caller-composed runtime.
State, security and shared-resource plans remain separate composable projections.
No sockets, databases, grants or policies are provisioned by planning.

| Input | Result / enforcement |
| --- | --- |
| `tunnel.quic.addr`, `interservice.https_addr` | `Addresses()` returns the socket bind addresses; caller opens them later |
| `tunnel.tls_handshake_timeout` | Native QUIC total handshake timeout, half of it as idle timeout; accepted range 2ms…5s |
| `tunnel.register_timeout` | Registration bootstrap deadline and ack register_ms; exact integer milliseconds, 1ms…10s |
| `tunnel.max_tunnels` | Local native connection ceiling |
| `tunnel.max_inflight_per_tunnel` | Ack/native session inflight ceiling, 1…1000, capped against service advertisement during negotiation |
| `security.rate_limits.registrations_per_service_per_minute`, `registrations_per_ip_per_minute` | Existing bounded registration token buckets before grant hashing/SQL |
| `security.resource_limits.external_connections`, `connections_per_ip` | Dedicated TCP pre-TLS quotas; optional shared pool remains additional |
| `buffer_bytes_global`, `buffer_bytes_per_service`, `buffer_bytes_per_tunnel` | Native reservations, per-service memory reservation, and advertised bounded session buffer |
| Explicit `TransportReservations` | Native per-IP/handshake quotas, concurrent registration/IP tracking bounds, measured connection overhead, receive windows and active HTTP request/probe ceiling |

Defaults match the schema: QUIC enabled, addr :7171, handshake/connect 5s,
registration 10s, 1000 tunnels/inflight, registration rates 30/10, TCP 5000/50 and
buffer budgets 512MiB/64MiB/16MiB. Operator reservations have no guessed defaults;
zero/unsupported reservations fail. They must be justified by platform/resource
measurements and remain distinct from request body sizes or stream/session quotas.

The policy uses the pinned protocol types/constants, not fixture data. It requires
minor 1 with the baseline capabilities, credential_generation and
quic_quiescent_fence, plus configured service readiness. mount_discovery is offered
without making it mandatory for a peer that does not advertise it. This matches the pinned
SDK's production QUIC driver/service boundary; no fallback to legacy registration
or missing readiness occurs. Policy read/write/cancel/status/drain/readiness values
remain the supported defaults. Capability names do not by themselves establish
WebSocket/Hijacker or complete production acceptance.

The existing runtime currently fixes QUIC keepalive/idle to 15s/45s and shared
graceful budget to 30s. This plan accepts only equivalent configured durations for
those fields. connect_timeout must remain 5s: the server has no dialer, and this
projection does not implement outgoing connect behavior. The pinned SDK bootstrap
always parses control frames up to 65536 bytes; `max_control_message_bytes` must
remain 65536 until that boundary can honor a smaller configured limit. Nondefault
values are rejected, not rounded, clamped or accepted as inert configuration.

The plan calls `quictunnel.ValidateRuntimeSettings`, an IO-free validator shared
with the actual transport/admission settings normalization. It checks wire limits,
ack size, receive-window/native budget compatibility, registration gates, timer
bounds and prepaid native lease/command-history capacity. Runtime construction
still requires real identity, owner, stores and security sources. Validation alone
does not authenticate, authorize or open a runtime. Capabilities returned by Bind
are detached and existing owned settings/overrides are rejected.

The shared constructor test now maps state/security/transport/shared resources
from one validated document and supplies explicit epochs/revision/reservations.
Its stores are provisioned deliberately by the harness. A separate real mTLS QUIC
test sends no stream-0 registration and verifies that a tightened registration
deadline closes the connection through the bootstrap protocol-error boundary.
There is no replay-warmup bypass or signed business dispatch in these tests.

This projection does not map public browser/Admin listeners, outgoing SDK dialing,
WSS, HTTP response-header/body-idle/overall deadlines, WebSocket timeouts, target or
session/stream/FD budgets, global signed request rates, grants/access publication,
JWT/JWKS or a complete launch-field inventory. Those remain required before a full
launcher can accept a deployment. Inactive WSS and other deferred sections are not
claims of supported runtime behavior. The shared pool counts charged reservations,
not measured RSS or all resource use.
