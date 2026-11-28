# Signed HTTP admission and deadlines

`Config.GlobalRate` is one fixed token bucket for the dedicated listener, across
all callers. A positive PerSecond/Burst (up to 2147483647) enforces the configured
ceiling; the all-zero API value preserves the older unlimited behavior. Deployment
mapping always supplies positive schema defaults 1000/2000. The bucket starts with
a burst, refills by elapsed time, uses constant state and creates no IP/user map or
queue. Backward clock movement does not replenish tokens.

The gate runs after the HTTP parser/mTLS handshake and before peer metadata,
signature/JWT, key/control/replay work. Rejected requests receive 429 and do not
reserve a nonce or dispatch. `ComposeRuntimeHandler` places the same gate before
shared-runtime readiness/store checks and applies it exactly once. It does not
rate-limit TLS handshakes, direct trusted Ready API calls or other listeners;
connection/handshake budgets still apply. Multiple server instances need an
explicit aggregate owner; separate buckets are not a shared process-wide limit.

`Config.HTTP` supplies response-header timeout, blocking-body-operation idle
budget and optional overall request timeout. Zero header/idle API fields select 60s;
zero overall disables only the HTTP overall budget. Negative durations fail config.
The existing signed exchange security lease remains at most 5s, further shortened
by certificates/grants/accepted keys/user/recipient state and parent context. HTTP
budgets can shorten these limits and never renew or extend them. Long SSE/WS
security renewal remains separate work.

Overall timing starts before shared readiness/authentication. Callback cancellation
remains cooperative; no helper goroutine abandons a callback, pumps a body or frees
its ownership on timeout. Response-header timing starts after request upload EOF
or the declared ContentLength has been consumed (immediately for an empty body),
and stops on response headers. Completed upload read deadlines are cleared so they
do not terminate an active streaming response. It is not a response lifetime limit.
A transport that refuses to consume a body or honor context cannot be forced to
finish by this wrapper; ownership remains with that operation.

Upload/download body reads and client writes/flushes have bounded blocking-operation
idle timers. Successful operations permit further progress; backpressure between
read operations is not timed as a second input reader. Cancellation reaches the
request context and relevant network read/write deadlines, without buffering a
whole body. Deadline arming is synchronized with cancellation so it cannot restore
a future deadline after cancellation. A recorded operation-timeout cause preserves
408/504 classification even when a socket read deadline cancels the parent first. Context wakeup callbacks finish before handler
cleanup returns. Body readers and transport/Close operations must honor cancellation;
this is not permission to release resources while a broken implementation still runs.

Before final response headers, response-header/overall/downstream timeout maps to 504
and upload idle to 408. Diagnostic error delivery is best effort within the existing
security/socket limits. After final headers, a streaming timeout aborts the exchange
instead of appending another HTTP status/body. No business retry is introduced.
ReverseProxy retains its normal streaming copy/flush behavior; SSE can outlive the
header budget while body operations keep making progress. The wrappers preserve
ResponseController access to the underlying writer and do not modify signed URI,
Host or signature metadata. A transport request is cloned before its Body is wrapped.

`deployment.BindHTTPPolicy` maps routing response_header_timeout/body_idle_timeout/
request_timeout and security.rate_limits signed_per_second/signed_burst, with schema
defaults and override rejection. StatePlan uses the same signed rate/burst for replay
capacity validation. Other routing/body-size/WebSocket/session/target/FD limits,
browser ingress, full launch-profile validation and production/load acceptance remain
outside this boundary.

Tests use real mTLS signed ingress with a controlled transport/replay store for
header/overall timeouts, idle upload 408, idle/active SSE and security-deadline caps.
They check exactly-once rate admission before runtime work and unchanged replay/
dispatch counts on 429. A delayed upload/backpressure case verifies that upload time
is not charged as response-header wait. These are not full signed exchanges through
the shared QUIC runtime after the real 120s replay recovery barrier.
