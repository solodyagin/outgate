# Общий runtime подписанного service ingress и QUIC

`OpenSQLiteRuntime(Config)` связывает выделенный подписанный HTTPS listener с
`quictunnel.SQLiteRuntime`. QUIC runtime единолично открывает существующие control
и replay SQLite stores; HTTP admission использует те же handles. Повторного
`OpenSQLite` и второго restart barrier нет. Отсутствующее состояние не создаётся.

`Config.Service` задаёт authorities, attribute headers, JWT verifier и response
rewrite. TLS identity, trust domain, registry, replay namespace/store, resolver
и admission callbacks задаёт общий runtime; overrides запрещены. `Config.State`
задаёт accepted HMAC key source, фиксированные caller rate limits и optional
user-security check. Store внедряется владельцем. Конфигурация QUIC валидирует
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

Ошибка любого Serve запускает общую остановку. `Shutdown(ctx)` немедленно
запрещает новые handlers/probes и QUIC admission/resolution, отменяет HTTP contexts
и закрывает сети. QUIC отправляет close до закрытия UDP. Stores закрываются только
после возврата всех HTTP handlers/probes и native QUIC owners/checkers. Истечение
caller context возвращает ошибку, сохраняя ownership; cleanup продолжается фоном,
повторный Shutdown может дождаться его завершения. Вызывать Shutdown обязательно
и после ошибки Serve. Прямой `quictunnel.Stop()` закрывает только admission/сеть;
composing owner обязан затем вызвать Shutdown после своих store users.

Это boundary для forced shutdown, а не завершённый production launcher.
Coordinated reconnect/drain с 30s graceful period, browser ingress, YAML mapping,
file/keyring/JWKS/certificate reload sources, служебный health listener,
aggregate process RAM/FD budgets, Admin mutation publication и discovery/revocation
endpoints остаются отдельной работой. TCP/QUIC reservations не доказывают RSS bound.

Lifecycle tests используют private fake owner для управляемых listener failures,
handler/health cancellation и overload. Отдельные real SQLite/UDP/TCP+mTLS tests
проверяют warmup refusal, единое ownership, сохранение обоих stores под blocked
health callback и cleanup неуспешного construction. Успешный signed HTTP→QUIC
streaming и запрет dispatch после replay-time mutation проверяются существующими
servicecall/quictunnel tests; полной acceptance общего production launcher нет.
