# Зависимости транспорта и хранилищ

Версии закреплены в отдельном тестовом модуле с Go 1.27.4. Адаптеры будут подключать проверенные зависимости в собственных модулях при реализации. Текущий gateway использует SDK `protocol/v1`. [Тестовый go.mod](../tests/dependencies/go.mod), [go.sum](../tests/dependencies/go.sum).

| Назначение | Версия | Лицензия модуля | Основание выбора |
| --- | --- | --- | --- |
| QUIC и HTTP/3 | `github.com/quic-go/quic-go v0.65.0` | MIT | `Transport.NewClientConn` и `Server.ServeQUICConn` работают с существующим `*quic.Conn`. Направление HTTP/3, исключение stream 0 из HTTP/3, streaming, отмена и CONNECT проверяются следующим сквозным spike. [HTTP/3 API](https://pkg.go.dev/github.com/quic-go/quic-go@v0.65.0/http3), [релиз](https://github.com/quic-go/quic-go/releases/tag/v0.65.0). |
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

Smoke-тесты проверяют выбор библиотек. Отдельными условиями приёмки остаются сквозной reverse HTTP/3 на нативных Linux/Windows, транзакции и recovery реальных SQL backend, OS owner lock, а также проверка production-артефактов.
