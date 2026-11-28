# Общий runtime подписанного service ingress и QUIC

`OpenSQLiteRuntime(Config)` связывает выделенный подписанный HTTPS listener с
`quictunnel.SQLiteRuntime`. QUIC runtime единолично открывает существующие control
и replay SQLite stores; HTTP admission использует те же handles. Повторного
`OpenSQLite` и второго restart barrier нет. Отсутствующее состояние не создаётся.

`Config.Service` задаёт authorities, attribute headers, JWT verifier и response
rewrite. TLS identity, trust domain, registry, replay namespace/store, resolver
и admission callbacks задаёт общий runtime; overrides запрещены. `Config.State`
задаёт accepted HMAC key source, фиксированные caller rate limits и optional
user-security check. `Config.RecipientKeyIDs` задаёт явную map recipient service →
active gateway signing key ID (1…256 entries, только известные registry services,
валидные service/key IDs). Map копируется при startup. После exact transport
resolution runtime получает этот ID через State.Keys для leg=outgategateway,
проверяет returned ID/32…4096 secret bytes/NotAfter и копирует secret. Затем
BindStateAdmission повторно сверяет тот же ID/bytes, durable revocations и lifetime;
после replay commit сохраняются прежние revalidation checks. Caller не выбирает
recipient key ID; неизвестный target, key source error/expiry/смена bytes не
вызывают fallback на другой ключ или transport. Store внедряется владельцем. Конфигурация QUIC валидирует
статический certificate/key; HTTPS использует отдельную копию DER/CA pool с тем же
ключом, TLS 1.3, required verified client certificate и без session tickets.
Private key и внешние sources должны оставаться неизменяемыми либо предоставлять
собственный безопасный rotation API.

Обязательный `KeyHealth` проверяет доступность авторитетного key source и выдаёт
freshness deadline не далее пяти секунд. Он дополняет настоящие control/replay
проверки и optional `Tunnel.AdditionalSecurity`, ограничивая также QUIC security
renewal. Все callbacks обязаны соблюдать context. Проверка не заменяет per-call
accepted-key lookup и post-commit revalidation в `BindStateAdmission`.

После route selection resolver обращается только к `Session(route.Session)`.
Он не ищет новую сессию по instance ID. Durable replay commit, revalidation того
же caller/key/recipient, gateway signing и streaming остаются в существующем
servicecall pipeline. Business retry отсутствует.

`Serve(tcp, udp)` принимает оба sockets на первом валидном вызове. TCP ограничен
существующими global/per-IP pre-TLS quotas, QUIC — собственными admission/memory
reservations. `MaxRequests` ограничивает одновременно выполняющиеся HTTP handlers
и внешние `Ready` probes без очереди; перегрузка HTTP получает 429. `Ready`
проверяет работающий TCP listener и настоящую QUIC/publication/control/replay/key
readiness. Во время 120s replay warmup service ingress получает 503 до входа в
signed pipeline; registration/renewal могут продолжаться по правилам QUIC runtime.

`GracefulShutdown(ctx)` сразу запрещает новые HTTP handlers/probes и QUIC
admission/resolution и снимает readiness. HTTP server прекращает accept, сохраняя
активные requests; QUIC BeginDrain параллельно запускает Reconnect текущих exact
sessions. Общий deadline — minimum caller deadline и 30s; новый budget на каждый
listener/session не создаётся. Пока завершаются handlers/probes и reconnect
handshakes, HTTP base contexts, UDP и QUIC security renewal остаются живыми.
Legacy sessions без negotiated quiescent fence закрываются fail-closed.

После завершения всех участников либо истечения grace deadline остаток
отменяется: HTTP contexts/server, QUIC native connections и transport, затем UDP.
QUIC отправляет close до закрытия UDP. Stores закрываются только после actual
возврата всех HTTP handlers/probes и native QUIC owners/checkers. Истечение caller
context возвращает ошибку, сохраняя ownership; cleanup продолжается фоном.
Повторный GracefulShutdown не продлевает первый maximum budget; более ранняя
отмена caller его прерывает. Budget ограничивает graceful network period, а не
время ожидания callback, нарушающего cancellation contract.

`Shutdown(ctx)` сохраняет прежнюю immediate cancellation семантику и может
прервать уже начатый grace period. Неожиданная ошибка любого Serve также
немедленно прерывает grace. Ожидаемый http.ErrServerClosed после HTTP Shutdown не
считается отказом QUIC sibling; последующая настоящая UDP ошибка возвращается
из Serve. Shutdown/GracefulShutdown нужно дождаться и после ошибки Serve.
Прямой quictunnel.BeginDrain не закрывает shared stores; composing owner обязан
вызвать Stop/Shutdown после своих store users. Rejected Serve сохраняет caller
ownership sockets, включая shutdown до первого Serve.

Deployment launcher, browser ingress, полное YAML mapping, authenticated keyring/JWKS/certificate
reload sources, служебный health listener, aggregate process RAM/FD budgets,
Admin mutation publication и discovery/revocation endpoints остаются отдельной
работой. TCP/QUIC reservations не доказывают RSS bound.

Lifecycle tests используют private fake owner для управляемых listener failures,
handler/health cancellation и overload. Отдельные real SQLite/UDP/TCP+mTLS tests
проверяют warmup refusal, единое ownership, сохранение обоих stores под blocked
health callback и cleanup неуспешного construction. Успешный signed HTTP→QUIC
streaming и запрет dispatch после replay-time mutation проверяются существующими
servicecall/quictunnel tests; полной acceptance общего production launcher нет.

Graceful lifecycle tests проверяют оба порядка HTTP/QUIC completion без раннего
cancel, общий deadline/default30s, admission denial during grace,
immediate abort, UDP failure после intentional HTTP shutdown и timeout с retained
stores под blocked health callback. Real SQLite/QUIC/pinned SDK driver проверяет
validated reconnect во время replay warmup без его сокращения; blocked registry
cleanup сохраняет native quotas/store ownership и после forced stop. Полный
signed HTTP→QUIC exchange общего runtime после restart barrier и native Windows
runtime acceptance остаются отдельной проверкой.

Регрессия recipient signing-key wiring покрыта прямым тестом того же
bindRecipientAdmission, который вызывается production constructor: реальный
SQLite store принимает selected active key, отклоняет revocation и изменение
bytes между selection и durable recheck. Transport/registry admission в этом
тесте явно synthetic и не выполняет business dispatch. Startup file/env loader
добавлен отдельно в internal/keyring; authenticated reload и полное deployment
YAML mapping остаются следующими шагами.

`internal/keyring.Load` предоставляет bounded startup file/env HMAC source:
State.Keys=ring.Keys, KeyHealth=ring.Health, RecipientKeyIDs=ring.RecipientKeyIDs().
Его NotAfter задаётся явно; loaded configuration остаётся static до restart.
Источник закрывает владелец после actual runtime cleanup. Health проверяет только
локальное состояние keyring; durable revocations остаются в StateAdmission.
См. [границы и формат источника](../keyring/README.md).

`internal/deployment.PlanSharedSecurity` добавляет проверенный startup security
subset для QUIC-only shared identity: SAN, matching server identities/service CA,
Admin/service CA separation и конечные TLS/CA/HMAC deadlines. `sources.Bind(base)`
подключает TLS, State.Keys, caller limits, authorities и KeyHealth; complete YAML
mapping/launcher остаются отдельной работой. Runtime заимствует sources; владелец
закрывает их только после actual runtime cleanup. См. [границы mapping](../deployment/README.md).
