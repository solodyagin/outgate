# Матрица совместимости Outgate

Состояние на 2026-11-22. Матрица фиксирует совместимость контрактов и проверенной основы этапа 1. Результаты нативного сквозного spike относятся к коммиту `d08dfc1`. У gateway и SDK пока нет опубликованных релизов. SDK carrier `731af09` прошёл native Linux/Windows CI. Ordinary HTTP/3 milestone SDK `4d1d5bb` также прошёл [native Linux/Windows CI](https://github.com/solodyagin/outgate-sdk/actions/runs/45036861734). Gateway ordinary HTTP/3 transport `ca28008` прошёл [native CI](https://github.com/solodyagin/outgate/actions/runs/45037269461). NativeStreams lifecycle SDK `5ee439b` прошёл [native Linux/Windows CI](https://github.com/solodyagin/outgate-sdk/actions/runs/45038551182). Новый gateway BoundSession readiness/cleanup проверяется отдельно; Windows cross-compile не подменяет native runtime.

| Область | Зафиксированная версия или профиль | Подтверждение |
| --- | --- | --- |
| Go | 1.27.4 в модулях gateway, SDK и тестов зависимостей | Локальные проверки Linux amd64 и двухплатформенный CI. Поддержка более ранних версий Go пока не исследована. |
| Tunnel wire | Major 1, minor 1; minor 0 совместим; JSON Schema Draft 2020-12 | [Протокол](protocol.md), [схема](protocol.schema.json) и [golden fixtures](../tests/fixtures/protocol/v1/). Проверяются bytes, codecs и модели состояний. |
| QUIC / reverse HTTP/3 | `quic-go v0.65.0`, TLS 1.3, ALPN `outgate-tunnel/1`, bidi stream 0 для control | Сквозные тесты на Linux и Windows amd64 охватывают carrier, streaming, отмену и internal CONNECT. [Отчёт](quic-spike.md). |
| WSS | `coder/websocket v1.8.15`, TLS 1.3, subprotocol `outgate.tunnel.v1`, compression отключён | Smoke-тест binary message и отдельные тесты framing, credit, cancellation и state machine. Сквозной WSS adapter проверяется на этапе 3. |
| Admin API | API version 1 через `X-Outgate-Admin-API-Version: 1`, спецификация OpenAPI 3.1.0 | Проверяются схема, операции, examples и описание ошибки `unsupported_admin_api_version`. Runtime endpoints проверяются на этапе 4. [OpenAPI](admin-openapi.yaml). |
| Конфигурация | JSON Schema Draft 2020-12 для gateway, Admin Web BFF и credentials | Проверяются схемы, примеры development/production и форма SQL-профилей. [Gateway](config.schema.json), [BFF](admin-web.schema.json), [credentials](credentials.md). |
| SQLite | `modernc.org/sqlite v1.62.0`, ядро 3.54.1, `modernc.org/libc v1.80.1`, без CGO | Smoke-тест WAL/FULL, видимости commit и уникальности. Control/replay/session, миграции и recovery проверяются с адаптером. |
| PostgreSQL | `github.com/jackc/pgx/v5 v5.13.0` | Проверяется конфигурация клиента `verify-full` с TLS 1.3. Поддерживаемые major/minor версии сервера определит прогон общего SQL-набора. |
| Redis | Опциональный replay backend | Описана условная конфигурация. Совместимость проверяется при поставке адаптера. |
| SDK, подключённый gateway | `v0.0.0-20261122203205-dfb593d5c065` | Gateway использует wire types, QUIC carrier/HTTP и sessionstate NativeStreams для BoundSession readiness/cleanup и service-side quicsession driver; public Client lifecycle/reconnect доступен через explicit Connect callback. Тестовый модуль закрепляет ту же revision; это версия исходников для сборки. |
| Зависимости и SBOM | Закреплённый граф тестового модуля, CycloneDX для Linux и Windows amd64 | CI сверяет состав тестового бинарника и контрольные суммы. Бинарники релиза получат собственные SBOM. [Версии и лицензии](dependencies.md). |

## Платформы

| Цель | Подтверждено | Приёмка релиза |
| --- | --- | --- |
| Linux amd64 | Нативные проверки контрактов, реестра, тестового модуля и reverse HTTP/3. Race detector для gateway и SDK предусмотрен на Linux. | Зафиксировать проверенные дистрибутивы и выполнить общий integration/security/storage suite. |
| Windows amd64 | Нативный CI тестового модуля, включая reverse HTTP/3 с `CGO_ENABLED=0`. [Windows job](https://github.com/solodyagin/outgate/actions/runs/44946979301/job/136976325174). | Проверить конкретные сборки Windows Server 2022/2025 для production и Windows 11 для разработки и стенда. Для production проверить нативные `.exe`, Windows Service, ACL, firewall и оба SQL backend. |

## Совместимость при выпуске

- Gateway и SDK выпускаются независимо с SemVer. Gateway release N проверяется с SDK N и предыдущим опубликованным minor того же major, когда он существует. Для каждого сочетания проверяются QUIC и WSS. Релизных сочетаний, прошедших проверку, пока нет.
- Wire version согласуется при регистрации. Peer выбирает major явно. При совпадающем major согласуются минимальный minor и пересечение capabilities. Другой major или отсутствующий обязательный capability отклоняются до трафика с `unsupported_protocol_version`. Breaking changes требуют нового major, совместимые optional extensions вводятся через minor.
- Версии Admin API и DB schema независимы от wire и SemVer. Номер DB schema — отдельное монотонно возрастающее целое. У control/replay/session хранилищ пока нет выпущенных миграций или списка совместимых schema versions.
- Для каждой миграции релиз фиксирует source/target schema, необходимость backup и совместимые бинарники. Бинарник принимает только перечисленные версии схемы. Откат бинарника разрешён при поддержке текущей схемы. Для остальных случаев применяется документированная offline migration или restore с восстановлением security state и recovery barrier. Автоматический downgrade БД не предусмотрен.
- Обновление gateway использует drain/reconnect. Старые HTTP/SSE/WebSocket операции завершаются или закрываются по контракту текущей сессии. Требования к проверке релиза перечислены в [матрице приёмки](acceptance-matrix.md) и [ТЗ, §4.7](requirements.md#47-фиксация-wire-контракта-и-совместимость-версий).
