# Карта контекста gateway

Читайте эту карту, актуальную «Точку продолжения» в `../../project-notes/implementation-status.md` (если доступна), затем только нужные разделы и затронутый код с тестами. Карта не заменяет нормативные требования и не подтверждает готовность реализации. Для SDK используйте его [карту](https://github.com/solodyagin/outgate-sdk/blob/main/docs/context-map.md); локально — соседний checkout `../outgate-sdk` от корня gateway.

| Задача | Разделы нормативного контракта | Код / проверки |
|---|---|---|
| Регистрация, пути, rollout, active-passive | ТЗ 3.2–3.5, 3.16–3.18; protocol 3 | `internal/registry`, SDK `protocol/v1`; `package ./internal/registry` |
| QUIC transport, admission, cleanup | ТЗ 3.7, 4.2, 5.6; protocol 5, 8, 11–12; [spike](quic-spike.md) | `internal/transport/quictunnel`; SDK `transport/*`, `sessionstate`; `package ./internal/transport/quictunnel` |
| Wire codecs / WSS state | ТЗ 4; нужное сообщение в protocol 2–8, лимиты 11–12; нужный `$defs` в schema | SDK `protocol/v1`, `wssstate`, `sessionstate`; `tests/fixtures/protocol/v1`; `contracts` и соответствующие SDK packages |
| Подписи, JWT, incoming authorization / replay | ТЗ 3.12, 3.14–3.16, 5.5.1–5.5.5, 5.6; protocol 9 | [`internal/servicecall`](../internal/servicecall/README.md), SDK `httpsig`, `delegation`, `delivery`, `replay`; `package ./internal/servicecall ./internal/registry` |
| Client lifecycle, credentials / renewal | ТЗ 3.10, 3.21, 3.25, 5.6, 6.5; protocol 8; [credentials](credentials.md) | SDK `client`, `transport/quicsession`; `credential-provider.schema.json`, `deployment-grant.schema.json` |
| Discovery / mount / service HTTP | ТЗ 3.14, 3.16, 3.22; protocol 9–10 | `discovery.schema.json`, `tests/fixtures/discovery/v1`, SDK `client/discovery*`, `service_http*`; `contracts` |
| Config / Admin API / storage | ТЗ 3.9, 3.19–3.20, 3.23–3.26, 5.5, 6; соответствующие критерии 8 | `internal/controlstate` (SQLite revocations/operations/outbox), `config.schema.json`, `admin-openapi.yaml`, `admin-web.schema.json`, `tests/verify_*.py`; `package ./internal/controlstate` и `contracts` |
| Зависимости / SDK pin / платформы | ТЗ 2.3, 5.4, 5.5.7, 10.3 | `go.mod`, `tests/dependencies/go.mod`, [dependencies](dependencies.md), [compatibility](compatibility.md), SBOM; `full` и отдельный Windows compile |
| Шаблон сервиса | ТЗ 3.10–3.12, 3.16, 6.5, 10.3; [service-development](service-development.md) | Отдельный service-template repository; состояние сверять по коду, не по примерам ТЗ |

Номера относятся к [ТЗ](requirements.md) и [protocol](protocol.md). Wire/schema/fixtures принадлежат gateway; изменения синхронизируются с SDK по [правилам snapshot](https://github.com/solodyagin/outgate-sdk/blob/main/docs/contract-snapshot.md). Не редактируйте fixtures ради прохождения реализации.

## Как читать и ставить задачу

1. Уточните ожидаемое поведение и критерий завершения; выберите строку таблицы.
2. Найдите заголовки через `rg -n '^#{1,4} ' docs/requirements.md docs/protocol.md`; прочитайте нужные разделы, связанные ограничения и критерии приёмки из ТЗ 8. Для schema найдите определения через `rg -n '"\$defs"|"<имя>"' docs/protocol.schema.json` и прочитайте определение со связанными `$ref`.
3. Найдите symbols/вызовы через `rg -n '<symbol>' internal`; читайте реализацию и соответствующие тесты. Расширяйте контекст при изменении границ пакетов или контракта. Не выводите целиком ТЗ, schema, историю статуса и все тесты без необходимости.
4. Во время изменения используйте целевые проверки; перед завершением — обязательные проверки из [checks.md](checks.md) и `AGENTS.md`. Успешный локальный набор не равен production/platform acceptance.

Шаблон задачи: «Изменить поведение … при условии …; контекст: разделы …, файлы …; сохранить инварианты …; готово, когда сценарии … проходят». Конкретный список файлов — отправная точка, а не запрет проверять связанные места.
