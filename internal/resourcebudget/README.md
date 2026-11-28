# Shared connection reservations

`Budget` is a fixed, nonblocking admission pool for connection count, actual peer
IP count and positive charged bytes. It is independent of sockets/storage and
creates no workers, queues or expiry timers. Limits are immutable; total/per-IP
connection ceilings are 1–1000000. Byte arithmetic checks remaining space before
addition, including at int64 limits. Peer entries exist only for accepted leases
and are bounded by the connection ceiling; IPv4-mapped IPv6 addresses share the
same peer key. Invalid/scoped addresses and nonpositive charges are rejected.

`Acquire` atomically acquires one connection and its charge, or returns an error
without creating peer state. `Lease.Release` is idempotent and thread-safe. Leases
must not be copied. No context cancellation/timeout automatically releases a live
owner. `Stats` reports counts/charged bytes without exposing addresses; it does not
measure allocations or OS state. Sharing requires the same pool pointer; separate
pool instances do not establish a global bound.

The TCP quota listener reserves before TLS. It retains the lease until underlying
connection Close returns; concurrent/repeated Close waits for the same operation
and releases once. Closing only a listener does not release accepted connections.
The QUIC post-Retry gate reserves before native TLS allocation, using its existing
complete charge: protocol buffer reservation + native connection receive window +
operator-supplied connection overhead. Unattached cancellation releases as before;
an attached worker retains its reservation through admission, drain and actual
cleanup. Its existing per-listener/per-service reservations still apply.

The gateway's optional `Config.Resources` installs one pool into both paths;
`TCPConnectionBytes` is a required positive operator-measured reservation ≤1 GiB.
Separate subordinate shared-pool overrides are rejected. Standalone servicecall and
QUIC runtimes can also receive a pool explicitly. A nil pool preserves existing
per-listener limits; it is not evidence of a global resource limit.

`deployment.BindSharedResources` explicitly selects a conservative shared-ingress
policy: schema external_connections/connections_per_ip ceilings apply to TCP and
QUIC combined, and buffer_bytes_global bounds their combined charged bytes.
Omitted fields default to 5000/50/512 MiB. It does not allocate budgets for future
listeners or weaken existing local/per-service/handshake quotas. All actual buffer
sizes/overheads must still be supplied and validated by their runtime owner.

These reservations cover connection admission in the participating paths. They
do not measure or bound process RSS, all protocol/library/Go overhead, active HTTP
handler/stream buffers, UDP listener/socket descriptors, database FDs, source
snapshots, filesystem cache or CPU. Request/session/FD/rate budgets, budgets for
other listeners, fairness and load acceptance remain separate requirements.
Charging a TCP connection does not keep its reservation after socket Close for an
independently still-running HTTP handler; such work needs its own resource owner.

Tests cover count/bytes/per-IP competition in both directions across real TCP and
the native QUIC admission hook, overflow/boundaries, IP normalization, concurrent
acquire/release, TCP blocked Close, unattached cancellation and real QUIC blocked
cleanup after forced stop. A shared-gateway test uses a real mTLS QUIC connection
to exhaust the pool and checks TCP rejection before TLS; it does not register a
service or dispatch a signed business call. SQLite warmup and source/store cleanup
retain their existing contracts.
