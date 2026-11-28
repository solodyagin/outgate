# Outgate — Reverse API Gateway

Для разработки: [карта контекста](docs/context-map.md) и [локальные проверки](docs/checks.md).

Репозиторий: [solodyagin/outgate](https://github.com/solodyagin/outgate). Реализация [технического задания](docs/requirements.md). Контрактная приёмка этапа 1 пройдена локально. Работающий шлюз и релиз SDK входят в следующие этапы.

- `docs/` — нормативные требования и протокол.
- [OpenAPI 3.1 для Admin API](docs/admin-openapi.yaml) — контракт команд, чтения состояния и безопасного поиска результатов операций.
- [Схема конфигурации gateway](docs/config.schema.json) и [схема Admin Web BFF](docs/admin-web.schema.json) описывают отдельные процессы. Примеры для проверки контракта находятся в [docs/examples](docs/examples).
- [Контракт deployment grant и ротации credentials](docs/credentials.md) связывает выдачу, регистрацию и атомарный источник пары.
- [Зависимости транспорта и хранилищ](docs/dependencies.md) фиксируют версии для следующего шага и команды проверок.
- [Матрица совместимости](docs/compatibility.md) и [матрица приёмки](docs/acceptance-matrix.md) связывают версии, требования и проверки.
- `tests/fixtures/protocol/v1/` — нормативный golden corpus.
- [outgate-sdk](https://github.com/solodyagin/outgate-sdk) — отдельный Go-модуль `github.com/solodyagin/outgate-sdk`, чистые wire codecs `protocol/v1` и проверяемая HTTP state machine `wssstate` без сетевого I/O.
- [outgate-service-template](https://github.com/solodyagin/outgate-service-template) — отдельный репозиторий шаблона сервиса; содержит README, реализация boilerplate ещё не начата.

Конечная поставка разделена на gateway, SDK и service-template repositories. SDK вынесен из этого repository; репозиторий service-template создан отдельно. Сам шаблон и versioned releases ещё отсутствуют. SDK реализует QUIC bootstrap/stream 0 и ordinary streaming HTTP/3. [`internal/transport/quictunnel`](internal/transport/quictunnel/README.md) связывает регистрацию и single-session RoundTripper на опубликованной закреплённой SDK revision. SDK service-side driver подключает readiness/control/graceful cleanup; SDK public `client` предоставляет lifecycle и sequential reconnect через внешний Connect callback. Встроенный QUIC dialer, static/callback/file credential source и proactive renewal с bounded drain/actual cleanup подключены; ordinary background ServiceHTTPClient подключён; NewServiceRequest/discovery helper подключён; WebSocket/Hijacker, полные transport adapters и production control state остаются в работе. Локальные `replace` не используются; файл `go.work` для сборки не требуется.

Пакет `internal/registry` моделирует владельцев префиксов, версии, rollout, active-passive и выбор маршрута. Он принимает уже авторизованные регистрации и команды с ожидаемой ревизией. Регистрация создаёт сессию без готовности; готовность сообщает управляющий слой. Долговременное состояние и аудит подключает runtime gateway. Для проверки путей и регистрации модуль использует закреплённый `protocol/v1` отдельного SDK.

`quictunnel.AcceptBound` связывает transport с registry/sessionstate: единственный status reader, freshness/security/expiry timers, readiness gate, повторная проверка выбранного handle и cleanup после окончания native HTTP exchanges. До готовности и после stale/revoke новые назначения запрещены; route ownership при разрыве сохраняется. Обязательный admission callback предоставляет проверенный допуск и durable решение. `quictunnel.DurableAdmission` подключает SQLite RegistrationOwner, bounded per-IP/service gates, negotiated ack и cleanup; обязательный security-source callback задаёт короткую lease и replay barrier. Bounded security renewal/controller проверяет live grant и control/replay health; отдельная freshness lease не продлевает hard credential/drain сроки. Production launcher и прочие security sources остаются runtime задачей. Для minor 1 negotiated quiescent fence подключает graceful drain/unregister обоих направлений. SDK `quicsession.Service` проверяется совместно с BoundSession на реальном mTLS/HTTP3: status/readiness, drain обоих направлений, crossed commands и streaming upload. Public Client lifecycle/reconnect реализован в SDK через explicit Connect callback; встроенный QUIC dialer принимает static/callback/file atomic credential snapshots и выполняет proactive renewal после локальной проверки новой пары с bounded drain/actual cleanup старой. SDK поддерживает подписанный ServiceHTTPClient, JWT-делегирование и логический discovery helper. Gateway discovery endpoint и virtual HTTP/1.1/Hijacker остаются в работе.

[`internal/servicecall`](internal/servicecall/README.md) предоставляет service mTLS listener для подписанных вызовов. Он проверяет caller и маршрут, резервирует nonce в SQLite и подписывает запрос выбранному получателю на QUIC. Запуск, state для grants/отзывов, discovery и обработку response mount headers подключает runtime.

## Проверка

Из корня gateway, Python 3.12+:

```bash
python3 tests/fixtures/protocol/v1/verify.py
python3 -m pip install -r tests/requirements-contracts.txt
python3 -B tests/verify_protocol_schema.py
python3 -B tests/verify_admin_openapi.py
python3 -B tests/verify_config.py
python3 -B tests/verify_credentials.py
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
```

В Windows используется `python` вместо `python3`. В PowerShell задайте `$env:GOWORK = 'off'` и выполните `go test ./...` и `go vet ./...`. CI gateway проверяет контракты и реестр на Linux и Windows, включая race detector на Linux. У SDK есть отдельные Go-проверки. [README SDK](https://github.com/solodyagin/outgate-sdk#readme).

SDK содержит локальный snapshot schema/fixtures, поэтому собирается и тестируется без gateway checkout. При изменении wire-контракта обновляйте ТЗ, protocol/schema, fixtures и SDK согласованно. Для соседних checkout побайтовая сверка из gateway:

```bash
cmp docs/protocol.schema.json ../outgate-sdk/docs/protocol.schema.json
diff -r tests/fixtures/protocol/v1 ../outgate-sdk/tests/fixtures/protocol/v1
```

Происхождение и порядок обновления snapshot описаны в SDK: `docs/contract-snapshot.md`.
