# Статус реализации

Обновлено: 2026-11-21. Начат этап 1 «Контракты и основа». Ни один этап ТЗ целиком ещё не закрыт.

## Точка продолжения

- **Текущая задача:** завершён проверяемый шаг этапа 1 — SDK codecs `request_start`/`response_start` и проверки HTTP-метаданных; следующий шаг — завершение stream control messages.
- **Завершённые шаги:** в отдельном SDK добавлены wire models, строгий decode обязательных/неизвестных/null/case полей, точная форма header pairs, сохранение повторений, HTTP token/value validation, Host и escaped URI без повторной сериализации, запрет ordinary hop-by-hop полей и неоднозначных Content-Length. Добавлены golden round trips, негативные/граничные тесты и два fuzz targets. Нормативные schema/fixtures и их SDK snapshot не изменены. Ранее реализованы register/ack/nack, выделен SDK и добавлена CI-проверка локальных путей.
- **Незавершённая работа:** остальные 14 control messages, session state machines, negotiated limits/budget и полный размер сериализованного HTTP header block, body/Content-Length accounting, Go signatures/replay, transport adapters и `outgateclient`. Versioned SDK release и boilerplate в отдельном template repository отсутствуют. Remote CI и native Windows runtime не подтверждены. Codecs не означают завершённую приёмку этапа.
- **Проверки текущей сессии (2026-11-21):** см. раздел «Проверки HTTP start» ниже; предыдущие результаты других шагов остаются в существующих разделах.
- **Блокеры:** для следующих control messages не выявлены. До QUIC adapter требуется собственный сквозной quic-go spike по ТЗ 2.3 с native Linux/Windows. Template tunnel integration требует `outgateclient` и SDK release.
- **Следующее действие:** сопоставить нормативные protocol/schema/fixtures и реализовать `request_end`/`response_end`, `window_update`, `cancel`/`cancel_ack`; затем добавить проверяемую stream state machine с credit overflow, ранним ответом, независимыми EOF и cancel races. Не подменять session/budget проверки codecs.

## Реализовано

| Часть | Код / проверка | Связь с контрактом |
| --- | --- | --- |
| Самостоятельный SDK module, standard library only | [SDK go.mod](https://github.com/solodyagin/outgate-sdk/blob/main/go.mod) | ТЗ 2.3, 10.3 |
| u64 decimal strings, предел uint64 | `primitives.go`, `TestU64` | Protocol §2 |
| Ограниченный JSON, duplicate keys, UTF-8 и depth | `json.go`, `TestJSONValidation`, fuzz target | Protocol §2, §5.2 |
| QUIC preface/control framing | `framing.go`, `TestQUICGolden`, truncation/boundary tests | Protocol §5.2; только serialization, не reverse HTTP/3 spike |
| WSS binary messages | `framing.go`, `TestWSSGolden`, fuzz target | Protocol §4.2; все существующие positive/negative binary fixtures |
| Строгий register parser и capabilities | `register.go`, `TestRegisterGoldenAndRejections` | Protocol §3.1–3.2; credential/permissions/conflicts отсутствуют |
| Строгие register_ack/register_nack и semantic validation | `register_response.go`, `register_response_test.go`: golden round trip, missing/null/type/case/unknown fields, JSON/extensions, ranges, session ID, paths/capabilities и retryable | Protocol §2, §3.3, §12; wire-контракт и нормативные fixtures сохранены |
| Сверка ack с исходным register | `RegisterAck.ValidateForRegister`: paths, minor/capabilities, concurrency, generation, readiness callback и production expiry | Protocol §3.1–3.3; без clocks/I/O, проверки credentials, актуальности expiry, durable state и готовности |
| Строгие request_start/response_start и HTTP metadata | `http_start.go`, `http_start_test.go`: golden round trips, closed fields, ordered pairs, tokens/CTL, Host, escaped URI, hop-by-hop и Content-Length, границы и fuzz targets | Protocol §2, §6.1; без session state, negotiated limits, полного serialized header block и body accounting |
| Prefixes, однократный decode, segment permissions | `path.go`, `TestPaths` | ТЗ 3.2–3.3; root authorization frontend выполняется будущим gateway |
| Инструкции разработки и CI | `AGENTS.md` и `.github/workflows/checks.yml` в каждом repository | Gateway: нормативный corpus; SDK: автономные fixtures и Go Linux/Windows |

Пути к Go-файлам в таблице относительны `protocol/v1/` отдельного [SDK repository](https://github.com/solodyagin/outgate-sdk). SDK хранит побайтовый snapshot schema/fixtures из gateway; исходный нормативный corpus остаётся здесь. Тесты codec не доказывают routing atomicity, сетевую совместимость, подписи или production security. Существующий Python verifier проверяет исходные HMAC vectors; Go signing/verifier ещё отсутствует.

## Следующая работа

1. Завершить модели/semantic validation остальных 14 control messages, начиная с end/window_update/cancel, затем state machines; проверить все negative control fixtures. Добавить Go signature profile с исходными HMAC/tamper vectors и replay interface.
2. Закрепить gateway/SDK контракты registry, pending/active/retired routes, revisions, rollout и active-passive с fake clock и отрицательными тестами. Реализовать gateway отдельным модулем без обратной зависимости из SDK.
3. Доставить недостающие артефакты этапа 1: Admin OpenAPI, config schemas, grant/provider schema, acceptance matrix всех обязательных требований, полноценную compatibility matrix. Текущая таблица ниже покрывает только начальную основу.
4. Выбрать и зафиксировать transport/storage dependencies после compatibility/security/license проверки. Выполнить обязательный quic-go spike из ТЗ 2.3 до начала этапа 2.
5. Затем QUIC/WSS adapters и outgateclient, gateway, Admin API/BFF, хранилища, отдельно выпускаемые SDK и service template, platform/security/load acceptance.

## Текущая совместимость

| Область | Состояние |
| --- | --- |
| Toolchain | Зафиксирован Go 1.27.4, использованный для начальной реализации; minimum Go/backward compatibility ещё не исследованы |
| Wire | Major 1 / minor 0; codecs по существующим fixtures |
| Linux amd64 | Локальные unit/race/vet проверки; команды и результаты сообщаются при изменении |
| Windows amd64 | Cross-compile доступен; native CI задан, локальная runtime-приёмка не выполнена |
| SDK / gateway N и предыдущий minor | Нет released SDK/gateway, compatibility integration не выполнена |
| Dependencies / SBOM | В SDK только Go standard library; transport/SQL зависимости и release SBOM ещё не выбраны/сформированы |

Production запуск не реализован. Отсутствуют sockets, application proxy, credentials verification, durable control/replay/session stores и Admin Web. Инструкций публичного развёртывания на этом этапе нет.

## Проверки HTTP start

Текущая сессия 2026-11-21, Linux amd64 / Go 1.27.4:

- SDK: `GOWORK=off GOPROXY=off go test ./...`, `go test -race ./...` и `go vet ./...` с теми же flags и отдельным временным GOCACHE — PASS. Внешние dependencies не добавлены.
- Golden request_start/response_start сохраняют все поля и порядок headers; negative fixture ordinary_101 отклоняется. Проверены missing/null/type/case/unknown fields, точные пары headers, JSON/extensions, stream ID/u64, method/Host/URI, HTTP token/CTL/hop-by-hop, Content-Length, byte/count/status границы. Оба новых decoder fuzz targets по 5 секунд — PASS; это короткий smoke fuzz, не release acceptance.
- Windows amd64: `go build ./...` и `go test -c` для `protocol/v1` с `GOWORK=off GOPROXY=off GOOS=windows GOARCH=amd64` — PASS. Native Windows runtime и remote CI не запускались.
- Fixture verifier в gateway и SDK, побайтовая сверка schema/fixtures — PASS. Wire-контракт и нормативные golden bytes не менялись. Verifier не заменяет полную JSON Schema validation.
- Проверка локальных путей и её 5 unit tests в каждом repository, отдельная проверка новых Go-файлов и `git diff --check` — PASS. При подготовке коммитов новые Go-файлы добавлены в индекс; tracked-files scanner повторно охватил их — PASS.

Codecs проверяют wire/HTTP metadata, но не authentication/authorization, production Host allowlist, negotiated limits/buffer reservations, полный размер сериализованного HTTP header block, body eligibility для HEAD/204/304, EOF/Content-Length соответствие или session transitions. Эти проверки остаются у будущих adapters/state machines; транспортная приёмка не выполнена.

## Проверки документации шаблона сервиса

Предыдущая сессия 2026-11-21: локальные Git status/origin нового repository, согласованность упоминаний шаблона, относительные Markdown links и `git diff --check` — PASS. Менялись только документы, Go-проверки не повторялись. Ранее прошли fixture verifier в gateway/SDK, SDK race/vet, побайтовая сверка schema/fixtures и Windows cross-compile; это не native Windows runtime-приёмка. Remote CI и доступность GitHub на том шаге не проверялись.

## Проверки переименования

Предыдущая сессия 2026-11-21, Linux amd64 / Go 1.27.4:

- `python3 tests/fixtures/protocol/v1/verify.py` — PASS: 19 control message types, 13 WSS cases, 4 пересчитанных HMAC/tamper vectors, QUIC bootstrap. Полноценная JSON Schema validation и adapter integration этим скриптом не выполняются.
- Из `outgate-sdk/`: `GOWORK=off GOPROXY=off go test -race ./...` и `go vet ./...` с теми же environment flags — PASS; использован отдельный временный GOCACHE, registry не использовался.
- Windows amd64: `go build ./...` и `go test -c -o "${TEMP_DIR}/protocol-windows.test.exe" ./protocol/v1` (здесь `${TEMP_DIR}` обозначает временный каталог) с теми же flags и `GOOS=windows GOARCH=amd64` — PASS. Native Windows runtime-проверка не выполнена.
- Каждый из четырёх переписанных commits отдельно выгружен в snapshot: fixture verifier и offline `go test ./...` — PASS. Проверены все trees, paths и commit messages: прежних идентификаторов проекта нет. Авторы, даты и порядок коммитов сохранены; SHA изменились. Удалённых repositories/push нет.
- Контрольные JSON/frame golden bytes и bootstrap credential/frame payload сохранены; изменены только magic, ALPN, signature/header identifiers и соответствующие HMAC. Bootstrap тесты проверяют границы credential, неверный magic и прежний preface, kind, length и UTF-8; прежний preface отклоняется.
- Относительные Markdown file links и `git diff --check` — PASS. Dependencies не добавлены. Исходная история сохранена отдельно в локальном Git bundle; это локальная временная резервная копия, не release artifact.

## Проверки ack/nack

Предыдущая сессия 2026-11-21, Linux amd64 / Go 1.27.4:

- `python3 tests/fixtures/protocol/v1/verify.py` — PASS; нормативные fixtures и schema не изменены. Этот sanity verifier не выполняет полноценную JSON Schema validation.
- В `outgate-sdk/`: `GOWORK=off GOPROXY=off go test ./...`, `go test -race ./...` и `go vet ./...` с теми же environment flags — PASS. Для всех Go-команд GOCACHE указывал на отдельный временный каталог, поскольку штатный cache недоступен для записи; registry не использовался.
- Windows cross-compile с `GOWORK=off GOPROXY=off GOOS=windows GOARCH=amd64` и тем же `GOCACHE`: `go build ./...` и `go test -c -o "${TEMP_DIR}/protocol-windows.test.exe" ./protocol/v1` (здесь `${TEMP_DIR}` обозначает временный каталог) — PASS. Отдельная сборка production-кода выполнена при подготовке коммита; native Windows runtime-проверка не выполнена.
- По 5 секунд fuzz для `FuzzDecodeRegisterAck` и `FuzzDecodeRegisterNack`: `go test ./protocol/v1 -run '^$' -fuzz '^FuzzDecodeRegisterAck$' -fuzztime=5s -parallel=2` и аналогично для nack, с теми же offline/cache flags — PASS (246 и 74 280 запусков соответственно). Короткие прогоны не являются полной приёмкой протокола.
- `git diff --check` — PASS; проверены новые Go-файлы и форматирование. Изменения ограничены ack/nack, тестами и документацией; зависимости не добавлены. Gateway/transport integration и state machines этим шагом не проверялись.

## Проверки начальной реализации

Локально на Linux amd64 / Go 1.27.4:

- `GOWORK=off go test -race ./...` и `go vet ./...` — PASS.
- Покрытие `protocol/v1` — 89.7% statements; это не процент готовности ТЗ.
- По 5 секунд fuzz для `FuzzDecodeChunk` и `FuzzControlJSON` — PASS (около 276 тысяч и 91 тысячи запусков соответственно).
- `GOOS=windows GOARCH=amd64 go test -c ./protocol/v1` — PASS; получен тестовый executable, на Windows не запускался.
- `go list -m all` — только текущий SDK module, внешних module dependencies нет.
- Исходный `verify.py` — PASS: 19 типов control examples, 13 WSS cases, 4 HMAC/tamper vectors, QUIC bootstrap. Проверка 19 примеров в этом скрипте означает покрытие каталога сообщений, а не полноценную JSON Schema validation.

GitHub Actions workflow добавлен, но его запуск в удалённом repository в этой сессии не выполнялся.
