# Статус реализации

Обновлено: 2026-11-21. Начат этап 1 «Контракты и основа». Ни один этап ТЗ целиком ещё не закрыт.

## Точка продолжения

- **Текущая задача:** продолжить этап 1 с моделей и semantic validation control messages (пункт 1 раздела «Следующая работа»).
- **Завершённые шаги:** начальная основа SDK описана в разделе «Реализовано»; наличие кода и тестов сверено с репозиторием. Добавлены эта точка продолжения и правило её чтения/обновления в корневом `AGENTS.md`.
- **Незавершённая работа:** остальные 18 control messages ещё не имеют типизированных моделей и semantic validation в SDK; дальнейшие задачи перечислены в разделе «Следующая работа». Ни один этап целиком не принят.
- **Проверки текущей сессии (2026-11-21):** просмотрены код SDK, список fixtures, требования этапа 1 и состояние Git; до изменений рабочее дерево было чистым. Diff проверен: изменены только корневой `AGENTS.md` и этот файл; `git diff --check` — PASS. Go-тесты и fixture verifier повторно не запускались. Результаты в разделе «Проверки начальной реализации» записаны ранее и не являются свежим запуском.
- **Блокеры:** для следующего шага по control messages при сверке не выявлены. До QUIC adapter остаётся обязательным сквозной quic-go spike по ТЗ 2.3.
- **Следующее действие:** прочитать `outgate-sdk/AGENTS.md`, сопоставить `register_ack` и `register_nack` в protocol/schema и `tests/fixtures/protocol/v1/control-messages.json`; добавить их модели, строгий decode и semantic validation в `outgate-sdk/protocol/v1/` с positive/negative и граничными тестами по существующему контракту.

## Реализовано

| Часть | Код / проверка | Связь с контрактом |
| --- | --- | --- |
| Самостоятельный SDK module, standard library only | `outgate-sdk/go.mod` | ТЗ 2.3, 10.3 |
| u64 decimal strings, предел uint64 | `primitives.go`, `TestU64` | Protocol §2 |
| Ограниченный JSON, duplicate keys, UTF-8 и depth | `json.go`, `TestJSONValidation`, fuzz target | Protocol §2, §5.2 |
| QUIC preface/control framing | `framing.go`, `TestQUICGolden`, truncation/boundary tests | Protocol §5.2; только serialization, не reverse HTTP/3 spike |
| WSS binary messages | `framing.go`, `TestWSSGolden`, fuzz target | Protocol §4.2; все существующие positive/negative binary fixtures |
| Строгий register parser и capabilities | `register.go`, `TestRegisterGoldenAndRejections` | Protocol §3.1–3.2; credential/permissions/conflicts отсутствуют |
| Prefixes, однократный decode, segment permissions | `path.go`, `TestPaths` | ТЗ 3.2–3.3; root authorization frontend выполняется будущим gateway |
| Инструкции разработки и CI | корневой/SDK AGENTS.md; `.github/workflows/checks.yml` | Проверки Linux/Windows после подключения к GitHub |

Пути к Go-файлам в таблице относительны `outgate-sdk/protocol/v1/`. Тесты codec не доказывают routing atomicity, сетевую совместимость, подписи или production security. Существующий Python verifier проверяет исходные HMAC vectors; Go signing/verifier ещё отсутствует.

## Следующая работа

1. Завершить модели/semantic validation остальных 18 control messages, headers/URI и state machines; проверить все negative control fixtures. Добавить Go signature profile с исходными HMAC/tamper vectors и replay interface.
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

## Проверки начальной реализации

Локально на Linux amd64 / Go 1.27.4:

- `GOWORK=off go test -race ./...` и `go vet ./...` — PASS.
- Покрытие `protocol/v1` — 89.7% statements; это не процент готовности ТЗ.
- По 5 секунд fuzz для `FuzzDecodeChunk` и `FuzzControlJSON` — PASS (около 276 тысяч и 91 тысячи запусков соответственно).
- `GOOS=windows GOARCH=amd64 go test -c ./protocol/v1` — PASS; получен тестовый executable, на Windows не запускался.
- `go list -m all` — только текущий SDK module, внешних module dependencies нет.
- Исходный `verify.py` — PASS: 19 типов control examples, 13 WSS cases, 4 HMAC/tamper vectors, QUIC bootstrap. Проверка 19 примеров в этом скрипте означает покрытие каталога сообщений, а не полноценную JSON Schema validation.

GitHub Actions workflow добавлен, но его запуск в удалённом repository в этой сессии не выполнялся.
