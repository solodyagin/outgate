# Зависимости транспорта и хранилищ

Версии закреплены в gateway и отдельном тестовом модуле с Go 1.27.4. Gateway transport boundary подключает опубликованный SDK `v0.0.0-20261128125504-8d6f0d2643d0` (`quiccontrol`/`quichttp`/`quicsession`/`sessionstate`) и `quic-go v0.65.0` с security pins `x/net`/`x/crypto`. Gateway/SDK ordinary HTTP/3 проверены на реальном mTLS connection; service-side control/readiness/graceful cleanup проверяется совместно с BoundSession. SDK public Client lifecycle/reconnect использует явный Connect callback; встроенный QUIC credential/dial adapter поддерживает static/callback/file snapshots и proactive renewal с bounded drain/actual cleanup; ordinary background ServiceHTTPClient реализован в SDK; NewServiceRequest/discovery helper подключён; Выделенный service listener подключает проверку подписанной доставки/JWT и SQLite replay из SDK. Gateway registration использует явное SDK RenewSecurity и bounded controller с real control/replay health; hard credential/legacy/drain сроки не продлеваются. WebSocket/Hijacker, полный production launcher и Admin mutation publication остаются в работе. [Gateway go.mod](../go.mod), [тестовый go.mod](../tests/dependencies/go.mod), [тестовый go.sum](../tests/dependencies/go.sum).

Gateway compiled test inventory хранится в [docs/sbom.cdx.json](sbom.cdx.json) и сверяется `python3 -B tests/verify_sbom.py` из корня на Linux/Windows amd64. В нём закреплены compiled external modules по каждой ОС и Go stdlib; тексты лицензий MIT/BSD-3-Clause находятся в `third-party/`. Это отдельный inventory от transport/storage smoke module и будущего release binary. `go mod verify`, race/vet и vulnerability scan проверяют текущий граф; изменение SDK revision требует синхронного обновления обоих test inventories.

| Назначение | Версия | Лицензия модуля | Основание выбора |
| --- | --- | --- | --- |
| Startup YAML | `go.yaml.in/yaml/v3 v3.0.6` | MIT AND Apache-2.0 | Поддерживаемая ветка YAML org; node API позволяет проверить duplicate/non-string keys и запретить aliases/tags до преобразования. Собственное разрешение scalar types соответствует offline fixtures. [Upstream](https://github.com/yaml/go-yaml/tree/v3.0.6). |
| JSON Schema | `github.com/santhosh-tekuri/jsonschema/v6 v6.0.3` | Apache-2.0 | Draft 2020-12, локально embedded нормативная schema, внешние загрузки запрещены. [Upstream](https://github.com/santhosh-tekuri/jsonschema/tree/v6.0.3). |
| Schema regex | `github.com/dlclark/regexp2 v1.12.0` | MIT | ECMAScript lookahead из нормативных patterns без изменения schema; 50ms per-match timeout, любое regex failure отклоняет весь документ. [Upstream](https://github.com/dlclark/regexp2/tree/v1.12.0). |
| QUIC и HTTP/3 | `github.com/quic-go/quic-go v0.65.0` | MIT | `Transport.NewClientConn` и `Server.ServeQUICConn` использованы для reverse HTTP/3 на одном QUIC-соединении в Linux spike. [HTTP/3 API](https://pkg.go.dev/github.com/quic-go/quic-go@v0.65.0/http3), [релиз](https://github.com/quic-go/quic-go/releases/tag/v0.65.0). |
| WSS | `github.com/coder/websocket v1.8.15` | ISC | Публичный API поддерживает ограничение сообщения, контексты чтения и записи, явный subprotocol и отключение compression. Тест проверяет бинарное сообщение через TLS 1.3. [API](https://pkg.go.dev/github.com/coder/websocket@v1.8.15). |
| SQLite | `modernc.org/sqlite v1.62.0`, движок 3.54.1 | BSD-3-Clause, лицензии встроенных компонентов отдельно | `database/sql` driver собирается при `CGO_ENABLED=0` для Linux и Windows amd64. Тест проверяет WAL/FULL на двух соединениях, видимость commit и уникальность ключа. Для этой версии закреплён `modernc.org/libc v1.80.1`. [Документация драйвера](https://pkg.go.dev/modernc.org/sqlite), [релиз SQLite](https://sqlite.org/releaselog/3_54_1.html). |
| PostgreSQL | `github.com/jackc/pgx/v5 v5.13.0` | MIT | Отдельный `pgx.Conn` предусмотрен для control owner lock, а `pgxpool` для ограниченных пулов остальных операций. Тест проверяет `verify-full`, CA, имя сервера, отсутствие fallback и параметры пула. [pgconn API](https://pkg.go.dev/github.com/jackc/pgx/v5@v5.13.0/pgconn), [релиз](https://github.com/jackc/pgx/releases/tag/v5.13.0). |

В будущей конфигурации PostgreSQL приложение задаёт минимальную версию TLS через `TLSConfig.MinVersion`, а `min_protocol_version` pgx относится к версии самого PostgreSQL-протокола. Адаптеру предстоит принимать параметры из проверенной конфигурации gateway и исключать неявные host/fallback и ambient libpq-настройки. Поддерживаемые версии сервера PostgreSQL закрепляются после испытаний с реальными экземплярами. [Настройки pgx](https://pkg.go.dev/github.com/jackc/pgx/v5@v5.13.0/pgconn#ParseConfig).

Первый скан выявил advisories в транзитивных модулях `golang.org/x/net` и `golang.org/x/crypto`. Закреплены обновлённые версии `v0.63.0` и `v0.59.0` соответственно. Повторный `govulncheck` для тестового кода с целями Linux и Windows amd64 завершился без находок. [Go advisory для x/net](https://pkg.go.dev/vuln/GO-2026-6866), [Go advisory для x/crypto](https://pkg.go.dev/vuln/GO-2026-6355).

## Воспроизведение

Из `tests/dependencies` на Linux выполните:

```bash
export GOWORK=off CGO_ENABLED=0
go mod verify
go test -mod=readonly ./...
go vet -mod=readonly ./...
python3 -B verify_sbom.py
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 -test ./...
```

В PowerShell задайте `$env:GOWORK = 'off'` и `$env:CGO_ENABLED = '0'`, используйте `python` для проверки SBOM. CI запускает smoke-тесты и сверяет SBOM на обеих ОС. Первичная загрузка модулей и запрос к Go vulnerability database требуют доступа к сети.

[SBOM CycloneDX](../tests/dependencies/sbom.cdx.json) перечисляет зависимости, которые компилируются в тестовый бинарник на каждой из двух ОС, а также Go standard library и встроенный SQLite. Извлечённые из zip модулей тексты лицензий и уведомления проверены для этого графа. Для релизных бинарников комплект уведомлений формируется по их собственному графу и включает вложенные уведомления SQLite/libc и Go. [Лицензия SQLite](https://sqlite.org/copyright.html), [уведомления modernc/sqlite](https://gitlab.com/cznic/sqlite/-/blob/v1.62.0/LICENSE-3RD-PARTY.md), [уведомления modernc/libc](https://gitlab.com/cznic/libc/-/blob/v1.80.1/LICENSE-3RD-PARTY.md).

Модуль gateway использует тот же SQLite pin через SDK replay и напрямую в controlstate. Controlstate также использует уже закреплённые UUIDv7 (`github.com/google/uuid v1.6.0`, BSD-3-Clause) и Windows owner lock (`golang.org/x/sys v0.50.0`, BSD-3-Clause). Версии и тексты лицензий не менялись; UUID теперь входит и в Windows compiled inventory. Отдельный smoke-модуль проверяет выбор библиотек, включая PostgreSQL. Результаты сквозной проверки обратного HTTP/3 на Linux и Windows приведены в [отчёте QUIC spike](quic-spike.md). Отдельными условиями приёмки остаются транзакции и recovery реальных SQL backend, OS owner lock и проверка production-артефактов.

Startup config validation использует эти три новых compiled modules; существующий `x/text`
остаётся на закреплённом pin. Тексты лицензий добавлены в `docs/third-party`, gateway
SBOM обновлён для Linux/Windows amd64. Go 1.27.4 race/vet и Windows build/test compile
проверяются вместе с gateway; отдельный transport/storage smoke module не импортирует
config и не меняет свой inventory. В текущей сессии `govulncheck v1.10.0 -test
./internal/config ./docs` на Linux не обнаружил уязвимостей; это результат проверки
достижимого кода, не гарантия отсутствия всех ошибок parser/schema libraries.
