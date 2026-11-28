# Gateway QUIC transport boundary

`Accept` принимает существующий quic-go connection и обязательный `quiccontrol.Authorize`. Успешный bootstrap/ack подключает single-session reverse HTTP/3 из опубликованной закреплённой SDK revision. Gateway не использует local replace, соседний SDK checkout или go.work для сборки и tests.

`Session` предоставляет `http.RoundTripper`, `Send`/`Receive` для session control и `Done`/`Err`/`Close`. Request ID sanitization, bounded inflight, streaming/SSE, independent EOF и cancel реализует SDK `transport/quichttp`; автоматические dial/retry/redirect отсутствуют. CONNECT/virtual HTTP/1.1/Hijacker пока не подключены.

Authorizer обязан проверить transport identity, grant, permissions, expiry/revocation, конфликты и durable commit до ack. `Accept` сам не публикует маршруты и не устанавливает readiness. Вызывающий слой должен обработать status/commands через sessionstate, связать accepted handle с registry, проверять готовность/security перед каждым назначением и исключить session по Done/неудаче ack. Эти integration layers и durable backend ещё предстоит реализовать. SQL/RAM-подмена production допуска отсутствует.

Tests выполняют реальный mTLS bootstrap из опубликованного SDK, ordinary HTTP с точным Host/raw query и удалением внешнего transport ID, status/drain одновременно с HTTP и cleanup при закрытии carrier. Authorization callback синтетический; эти tests не означают production acceptance или работающий gateway executable.

## Привязка к registry и sessionstate

`AcceptBound` создаёт `BoundSession` поверх того же transport и модели `sessionstate.NativeStreams`. Обязательный `Admit` возвращает fresh registry Session, согласованный ack и проверенные SecurityReady/SecurityDeadline после внешних identity/grant/permissions/conflicts/durable checks. Callback сам отвечает за rollback своей неудачной admission transaction. Встроенного RAM production backend или автоматической положительной security readiness нет.

`Registry.BindTransport` однократно проверяет живой handle, instance/service/version/paths/mode/transport и начальное unready состояние. Ack должен совпасть с актуальными registry paths/states/revision. После успешного binding transport владеет локальным handle: отказ ack исключает эту session, сохраняя durable route ownership; ошибка повторного/чужого binding не удаляет уже существующий transport.

Перед включением назначений владелец публикует соответствие Handle → BoundSession и вызывает EnableDispatch. Даже немедленный ready-status до этого не выставляет registry readiness и не открывает dispatch; EnableDispatch также не активирует pending routes.

BoundSession единолично получает status. Только свежий монотонный status ready вместе с security readiness и завершённым ready_not_before даёт SetReady(true). Непроверенный ObservedAt не заменяет receiver time. Таймер default 100ms, допустимо 0…1s с 0 как default; он двигает freshness/security/credential deadlines и без трафика. SetSecurity немедленно снимает/восстанавливает gate; более ранний security deadline нельзя продлить. Revoke отменяет активный HTTP и закрывает connection.

RoundTrip требует предварительного авторизованного route selection; он повторно проверяет именно выбранный registry handle, не выбирает другой instance и не делает retry. NativeLease удерживается до completion обоих направлений через SDK RoundTripWithCompletion, а не до response headers/EOF. Неготовый или stale handle не отправляет HTTP. Pending route activation и stable/canary policy остаются в registry/control layer.

Close(ctx) завершает transport немедленно и ограничивает ожидание local cleanup контекстом. Done означает завершение reader/timer и освобождение native exchanges/registry handle. При upload reader, нарушающем net/http concurrent Close contract, ожидание может истечь, но старый instance остаётся занятым до реального completion; повторная регистрация не обходит cleanup. Удаляется только Session handle, не retained route ownership; stale handles не изменяют replacement.

## Graceful drain (minor 1)

При negotiated required capability quic_quiescent_fence BoundSession поддерживает S-origin drain/drain_ack/unregister и G-origin Drain(ctx). Admission/ID allocation останавливаются немедленно; writer ждёт NativeActive=0, затем отправляет canonical frozen logical request-ID watermark. Частично завершённый HTTP/upload удерживает lease; deadline/revoke прерывает ожидание и не создаёт fake ack. Control queue ограничена MaxCommands и имеет одного writer; receiver/timer не блокируются на сетевой записи.

SDK `transport/quicsession.Service` проверяет G marker/command ledger, закрывает admission через HTTP Fence, ждёт actual handler cleanup, подтверждает G-origin drain и отправляет unregister. Reader продолжает принимать встречные команды; unregister дополнительно ждёт actual readiness invocation. После unregister_ack закрывает carrier нормально. Gateway исключает session из dispatch/подтверждает native cleanup до ack и сохраняет carrier, занятый instance ID и tunnel quota до нормального peer close в пределах оставшегося deadline. Close(ctx) по-прежнему немедленный, Drain(ctx) ожидает полную graceful последовательность.

Crossed уже переданные drain требуют обоих ack. Ещё не отправленный local drain intent присоединяется к peer drain; повторный Drain только сокращает deadline. Pending routes/ownership не удаляются. Без negotiated capability (включая minor 0) входящие native graceful команды закрывают connection fail-closed, а локальный Drain возвращает ErrControlNotIntegrated без смены transport/security режима.

Service-side control driver реализован в SDK; public `client.Client` предоставляет lifecycle/Close/security gate и sequential reconnect через внешний Connect callback. Встроенный QUIC credential/dial adapter поддерживает static/callback snapshots; file provider/proactive renewal, ServiceHTTPClient, internal CONNECT/virtual HTTP/1.1/Hijacker и production durable admission остаются следующими этапами. Низкоуровневые Session/SDK primitives не подменяют эти части фиктивной production identity.

Сквозные `TestServiceDriver*` запускают actual drivers обеих сторон из опубликованной exact SDK revision: readiness changes/security recovery, G/S/crossed drain, streaming upload с удержанием native lease и normal terminal close. Grant/durable admission в тестах остаётся синтетическим.

## Durable credential/ownership guard

`GuardRegistration(RegistrationGuard{Store, TrustDomain, Before, Commit})` creates an Admit callback for AcceptBound. It requires a real open controlstate store, a valid trust domain, a pre-admission rate/readiness gate and the registry owner callback. Before runs ahead of credential/storage work. The guard reads SPIFFE service/instance only from a verified TLS 1.3 leaf/chain, checks certificate lifetime, and acquires a durable credential-generation/local-ownership lease. It uses the same peeridentity helper as the signed HTTPS listener. Missing SAN, trust/identity mismatch, revoked/expired grant, changed binding/secret, older generation or duplicate owner never reaches Commit.

Commit must perform route permission/conflict checks and required durable registry commit/outbox/resync before returning a fresh, unready registry Session, complete RegisterAck and explicit SecurityReady. The guard supplies no RAM persistence substitute or permissive readiness default. It may retain the provided RegistrationLease to implement bounded periodic security checks. The guard pins ack credential expiry to min(certificate.NotAfter, grant.ExpiresAt) and echoes the accepted credential generation. It caps the renewable security deadline at five seconds and actual credential expiry; without renewal the connection closes rather than continuing indefinitely. During a replay recovery barrier the owner must renew a healthy-but-unready security lease, never claim readiness early.

Binding.Release attaches ownership cleanup to AcceptBound: ack/binding failure closes the connection and releases admission resources; normal cleanup first closes native QUIC/HTTP3, waits for handlers/body cleanup and control loops, removes the registry session, then calls Release outside the session mutex. A blocked application upload retains ownership until actual cleanup, even if Close(ctx) times out. Release is chained with the admission owner's cleanup and must not block forever. A Commit error still requires rollback/resync of its failed registry transaction; it may return a Binding.Release cleanup hook even with an error. AcceptBound closes the connection before invoking that hook and releasing credential ownership. GuardRegistration is intended for AcceptBound; any manual caller must honor nonzero Binding.Release on error as well as success. Committed generation fences remain durable after a later registration/ack error; the same pair can reconnect, and older pairs cannot regain access.

Tests exercise real mTLS/SPIFFE and QUIC with persisted grants, generation ownership and `controlstate.RegistrationOwner` snapshot/outbox publication. They cover successful registration, ack/bind/commit/pre-gate/identity errors, exactly-once release, retained durable ownership after lost ack and a blocked-upload cleanup boundary. The Commit callback can use `RegistrationOwner.Register` and build its ack from the returned registration; its Release must also clean up that fresh session on bind/ack errors. The owner never asserts SecurityReady. The bounded rate/readiness gate and production ack/cleanup wiring are available through DurableAdmission below. Bounded security renewal/controller is integrated below; Admin mutation publication, full production configuration and native Windows runtime acceptance remain separate work.

Guard failures use the existing nack table: bad/revoked/stale credentials are nonretryable auth_failed, active ownership is retryable duplicate_instance, resource quotas are retryable quota_exceeded, and opaque storage/commit errors remain state_unavailable. Error details are fixed and contain no credentials.


## Bounded durable admission factory

`NewDurableAdmission(DurableAdmissionConfig{Owner, TrustDomain, Limits, Policy,
Bound, Security})` wires the registration owner to real QUIC admission. `Accept`
uses the connection's socket peer IP; neither registration metadata nor forwarded
headers choose a rate-limit identity. Token buckets enforce independent per-IP
and per-service rates before grant hashing/SQL (profile values: 10/min per IP,
30/min per service, each with an equal initial burst). Service keys come only
from the owner's fixed configured principals and the verified TLS SAN. Failed
credentials still spend the attempt budget. IPv4-mapped addresses share the IPv4
bucket. A separate concurrency cap rejects excess work without a waiting queue.

The IP map is capped explicitly. Each attempt examines at most 16 entries for
idle-minute reclamation; depleted live buckets are never evicted to admit a new
IP. Full bookkeeping fails closed even if a later bounded maintenance pass could
reclaim more idle entries. QUIC uses the existing retryable `quota_exceeded` nack
and connection backoff; it has no HTTP Retry-After header. No wire fields change.
Listener-level connection/TLS handshake limits, aggregate RAM/FD reservations and
budgets across listeners remain required before this post-TLS admission stage.

`RegistrationPolicy` validates wire maxima and tightened protocol timeouts,
negotiates minor/capability intersection, caps inflight to the service's offer,
echoes credential generation and makes a fresh random 128-bit session ID.
Unsupported requirements, one-sided quiescent-fence opt-in and an oversized ack
are rejected before durable generation admission. Maximum-width timestamps and
revision are budgeted before persistence. Actual path states/service revision
come from the committed candidate. Production mode is mandatory; supplied Bound
registration/write timeouts must agree with policy, or be zero to derive them.

The required `Security` callback asserts healthy mandatory control/revocation/
replay sources, with a future ValidUntil at most five seconds away and the
trusted ReadyNotBefore barrier. It runs under a context capped at five seconds
before credential work and again after snapshot publication. It must honor that
context; no detached callback goroutines or unbounded retry queue are created.
A healthy replay warmup supplies a future barrier, rather than denying every
registration. The ack uses the later barrier, rounded UP to Unix seconds. Its
security deadline is bounded by both assertions and certificate/grant expiry.
Missing/stale/invalid/late assertions fail closed. A late health/lease/ack error
keeps durable ownership, closes the carrier and removes only its fresh session
before releasing the lease after native cleanup.

After Accept the runtime still publishes the transport mapping and calls
EnableDispatch. DurableAdmission now installs the bounded renewal controller
below. Pending routes still require administrative activation. Tests use real
mTLS/SPIFFE, SQLite and QUIC for registered-but-unready ack, rates, features,
health failures, peer closure before ack and exact lease cleanup.

## Renewable security freshness

The SDK pin supplies an explicit `sessionstate.RenewSecurity`, separate from
legacy hard Security deadlines. `Binding.RenewSecurity` opts a BoundSession into
one sequential checker; nil retains the old non-extending behavior. The factory
always installs a checker. `SecurityRenewal` defaults to 1s interval and 1s
per-check timeout; nonzero values may only tighten them. Shorter leases trigger
an earlier check at half their remaining lifetime. Deadline-aware timers and a native expiry alarm interrupt security/credential
limits independently of periodic ticks, a blocked callback, or a session/registry
lock held during SQL publication. The alarm retains separate hard/renewable
bounds and never substitutes a security error for a drain timeout.

Each factory renewal checks the publication barrier, private registration lease
ownership, current grant/expiry/generation/revocations, and the required Security
source. The new deadline cannot exceed the check's start +5s, source freshness,
certificate NotAfter or grant expiry. The factory's separate checker pool is
bounded by Limits.MaxConcurrent; saturation fails closed without queuing SQL.
Source error, timeout, stale assertion, lost ownership, revocation or closed
publication barrier invokes Revoke and cancels native exchanges. A future replay
barrier keeps a healthy initial session registered-but-unready; barriers cannot
be shortened by later assertions. A new recovery window after the old barrier
elapsed revokes the old transport (including admitted flows); reconnect can join
the new warmup. Renewal never refreshes peer status/probes, activates a route,
changes drain/fence intent, extends hard limits or revives a terminal transport.

`SQLiteAdmissionSecurity(control, replayStore)` provides a real source for
explicitly provisioned stores. It verifies control metadata/file/epoch health
and replay.Health; replay health also runs during warmup and returns the original
120s readiness deadline. Ready/Reserve retain the barrier and created cutoff.
Other mandatory runtime dependencies may compose this source with their own
checks; revocation/generation checks use the actual per-session control lease.
There is no automatic initialization, loss repair or RAM fallback.

At most one callback is outstanding per session. It runs outside the session
lock, with cancellation and the old lease deadline bounding its context. A
callback that ignores context cannot prevent transport revocation at expiry;
it retains its checker slot and registration ownership until it actually returns.
Native cleanup/Done wait for that return before releasing the lease/store, so
no replacement or unbounded callback accumulation can hide the old owner.
Late results cannot renew the closed model. Close schedules at most one stop
request and remains bounded by its caller context even while a registry lock
blocks cleanup; native cancellation and ownership release remain separate. Listener/aggregate memory budgets,
launcher/key loaders, Admin mutation publication, user-security propagation and
native Windows/runtime/storage production acceptance remain separate work.


## SQLite QUIC runtime

`OpenSQLiteRuntime(ctx, SQLiteRuntimeConfig, RuntimeLimits)` owns explicitly
provisioned control/replay stores, their recovered RegistrationOwner and
DurableAdmission. Missing files/snapshot, wrong epoch/watermark or invalid config
fail closed; it never initializes or repairs state. Admission.Owner and
Admission.Security must be nil because the runtime binds its own stores. An
optional AdditionalSecurity callback can only add a fresh <=5s dependency bound;
it cannot replace SQLite checks, shorten replay warmup or extend source expiry.
Server certificate NotAfter also caps admission/renewal health.

The static TLS profile requires TLS 1.3, service CA client verification and the
exact Outgate ALPN. Server DER chain, key match, leaf date and EKU are checked; DER and CA-pool state
are detached. Only standard ECDSA P-256/384/521, RSA (at most 8192 bits) and
Ed25519 private keys are accepted. Keys remain read-only; dynamic TLS callbacks,
custom signers, key reload and session tickets are not installed. QUIC v1 uses
no 0-RTT or datagrams, one incoming bidi stream for control stream 0, three
incoming uni streams for HTTP/3, fixed explicit receive windows, 15s keepalive
and 45s idle. Configured handshake total is at most 5s (idle is half that).

`Serve(packetConn)` takes exclusive ownership of one UDP socket on its first
call. Stateless Retry validates the initial source address before ConnContext
reserves global/per-IP connection and handshake quotas, before TLS allocation.
Unknown/unvalidated addresses allocate no ticket. IPv4-mapped addresses share an
IP budget; a connection remains charged to its initial verified address through
its lifetime, including later network changes. Pre-TLS excess is refused by
QUIC without credential work; service-budget excess uses the existing retryable
quota_exceeded nack/close code after bounded register parsing and before grant
mutation. A nack may be lost in a network/close race; peer close classification
remains quota_exceeded, not an authentication failure.

Every ticket reserves `Admission.Policy.Limits.BufferBytes +
ConnectionReceiveWindow + ConnectionOverheadBytes` against the runtime's global
buffer budget. After TLS identity is verified, it additionally reserves that
charge against the fixed configured service budget. Overhead must be chosen from
measurements: these are conservative admission reservations, not an RSS claim.
There is no live-ticket eviction or unbounded waiting queue. The advertised
native lease/command-history peak must fit the prepaid tunnel buffer at startup.
Failed handshakes release tickets on native context termination; accepted tickets
retain their connection/IP/buffer/service budgets until actual BoundSession
cleanup, even if the network already closed. A future launcher must account for
other listeners and aggregate process RAM/FD budgets separately.

The runtime inserts an exact `*registry.Session -> *BoundSession` mapping before
EnableDispatch. `Session(handle)` never looks up a reusable instance ID, chooses
a replacement or authorizes a request. It rejects stale, closed or stopping
handles. Callers still authenticate/authorize the selected registry decision and
recheck its route before dispatch. Registration/renewal never activates pending
routes. `Ready(ctx)` checks this component's listener, publication, SQLite and
additional dependency health; real 120s replay warmup remains not-ready while
healthy registrations and renewals are allowed. It is not whole-gateway readyz.
`Stats()` reports actual ticket/handshake/map counts and reserved bytes.

Always call `Shutdown(ctx)`, including after Serve errors or before Serve was
started. Shutdown stops resolution/admission first, sends normal closes while
UDP can transmit, then closes transport/socket and waits for tickets/workers.
Store close follows native exchanges and outstanding callbacks, preserving the
control owner lock throughout cleanup. Caller timeout does not drop ownership;
background completion continues and another Shutdown can wait again. A closed
listener or native context alone does not free an admitted ticket. ControlStore
and ReplayStore expose operations to trusted components; do not close them or
acquire registration leases outside this runtime's accounting. Shared ownership
with another registration transport needs a future combined lifecycle owner.

Tests use real UDP, mTLS/SPIFFE, SQLite and the pinned SDK. They cover startup
refusal/cleanup, missing state, handshake/IP/global/service/window budgets,
failed/stalled TLS, wrong ALPN, map-before-dispatch and stale-handle reconnect,
registered-but-unready warmup, static server certificate expiry, close-before-
socket shutdown, blocked registry/callback cleanup, retained store ownership and
shutdown/serve races. Full gateway launcher/YAML and key loaders, Admin mutation
publication, public/service ingress composition, WSS/WebSocket and native Windows
runtime/production load acceptance remain separate work.
