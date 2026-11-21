# Матрица приёмки Outgate

Критерии сопоставлены с [ТЗ, §8](requirements.md#8-критерии-приёмки) и [этапами поставки, §7](requirements.md#7-этапы-работ). Идентификаторы повторяют номера сценариев ТЗ. Для маркированного списка §8.3 используется порядковый номер пункта. Диапазоны включают обе границы, `*` означает все сценарии раздела.

Колонка «Этап» указывает, когда нужен полный сценарий. Колонка «Основа этапа 1» указывает существующие частичные проверки. Все runtime-сценарии ниже предстоит выполнить на работающих компонентах. Проверки этапа 5 повторяют применимую приёмку в production-профиле. Redis проверяется при поставке его адаптера.

## Контрактная приёмка этапа 1

| Часть 8.13.1 | Проверка | Граница результата |
| --- | --- | --- |
| Самостоятельность реализации (§2.3) | В gateway, SDK и `tests/dependencies` проверить manifests, resolved `go mod graph`, `go list -deps -test` для Linux/Windows, исходные импорты, vendor, CI и SBOM. Проверить происхождение кода по истории и [решению о референсе](upstream.md). | Только существующие Go-модули и тестовый SBOM. Release SBOM проверяется в 8.8.15. |
| Полный wire catalog и golden corpus (§4.7) | [Протокол](protocol.md), [schema checker](../tests/verify_protocol_schema.py), [независимый Python verifier](../tests/fixtures/protocol/v1/verify.py), SDK golden tests и побайтовая сверка snapshot. Go-сценарии `TestEarlyResponseAndCancelRace`, `TestIndependentEOFAndConsumption`, `TestWebSocketCancelRaces` проверяют state transitions. | Полные адаптеры повторяют corpus при своей приёмке. |
| Carrier и ALPN (§2.3, §4.7) | `TestQUICReverseStreamingAndCancellation`, `TestQUICReverseInternalConnect`; нативные результаты в [отчёте](quic-spike.md). | Тестовый peer, production интеграция на этапе 2. |
| HTTP signatures, user context, mount и межсервисные политики | [Протокол §§9–10](protocol.md#9-rfc-9421-signature-profile), `httpsig/TestGolden`, `TestRequestTampering`, `protocol/v1/TestPaths`, [схема Admin API](admin-openapi.yaml). | JWT, dispatch, policy enforcement, discovery и rewrite проверяются в 8.5, 8.6 и 8.13.3. |
| Реестр, версии и rollout | [Тесты реестра](../internal/registry/registry_test.go), в том числе `TestAtomicRegistrationAndRetainedOwnership`, `TestRolloutCoverageAndNoRedistribution` и `TestCandidateMountAndRouteRevision`. | Интеграция с реальными сессиями, хранилищем и аудитом проверяется в 8.1, 8.2 и 8.9. |
| OpenAPI и конфигурация (§6.5) | [Admin API](../tests/verify_admin_openapi.py), [конфигурация](../tests/verify_config.py), [credentials](../tests/verify_credentials.py) и workflow на Linux/Windows. | Сверка OpenAPI с зарегистрированными endpoints и их поведением относится к 8.13.1 этапа 4. |
| Fuzz corpus | SDK `protocol/v1`: `FuzzDecodeChunk` (framing), `FuzzDecodeRequestStart` (HTTP metadata и escaping). SDK `httpsig`: `FuzzVerifyProfile` (подпись, raw URI, canonicalization). | Seed corpus выполняется обычным `go test`. Для направленного fuzz-прогона запустить цели с `-run '^$' -fuzz` по одной. |
| Версии и артефакты (§4.7, §6.5) | [Матрица совместимости](compatibility.md) связывает Go, wire, Admin API, зависимости, ОС, SDK и DB schema с имеющимися результатами. | Совместимость выпущенных SDK/gateway и DB upgrade/restore требуют 8.13.10. |

Контрактная приёмка этапа 1 пройдена локально 2026-11-21 на Linux amd64 с Go 1.27.4.

- Проверены 19 типов control messages, 5 негативных примеров структуры, 13 WSS frames, QUIC bootstrap и 4 HMAC-вектора с подменой. Snapshot схемы и fixtures в SDK совпал побайтово.
- Прошли валидаторы 32 операций Admin API, 57 примеров запросов и ответов, профилей gateway/BFF и credentials. Номера всех 107 сценариев матрицы сверены с ТЗ.
- Прошли тесты и `go vet` трёх модулей, race detector gateway и SDK, короткие fuzz-прогоны framing, URI escaping и verification profile. В seed corpus добавлены повреждённые frames, допустимый и недопустимый escaping и повреждённый signature header.
- Проверены module graph, импорты для Linux и Windows, vendor, скрипты CI и тестовый SBOM. Просмотрена история добавления собственного кода и решения по upstream.
- Тестовые бинарники трёх модулей собраны для Windows amd64. Нативный Linux/Windows reverse HTTP/3 подтверждён ранее на `d08dfc1`. Новый шаг CI и расширенные fuzz seeds ожидают нативного прогона на текущих изменениях.

## Сквозные сценарии

Этап 2 реализует QUIC-варианты транспортных сценариев 8.1.1, 8.1.5–8 и 8.1.10–16. Этап 3 реализует соответствующие WSS-варианты и управление окнами из 8.1.9. На этапе 4 эти сценарии проходят общую приёмку в QUIC-only, WSS-only и mixed mode, где применимо.

### 8.1. Общая функциональность и транспорты

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.1.1 | Preserve/strip, метод, Host, query, заголовки и бинарное тело | 4 | QUIC spike проверяет часть HTTP metadata |
| 8.1.2 | SPA fallback, зарезервированный API и известный недоступный маршрут после restart | 4 | Реестр |
| 8.1.3 | Границы сегментов, вложенные префиксы, escaping и traversal | 4 | Реестр, SDK пути |
| 8.1.4 | Round-robin, mixed mode и авторизованные shared paths | 4 | Реестр |
| 8.1.5 | Атомарная регистрация и причины отказа: credentials, пути, instance, версия и лимиты | 4 | Реестр, SDK register |
| 8.1.6 | Disconnect, reconnect/restart и отсутствие повторной доставки | 4 | SDK lifecycle |
| 8.1.7 | Параллелизм, 429, ранний ответ, пустое тело и двунаправленная отмена | 4 | WSS-модель, QUIC spike |
| 8.1.8 | Большие тела, bounded memory и SSE flush | 4 | QUIC spike, WSS-модель |
| 8.1.9 | Медленный WSS stream и прогресс управления | 4 | WSS-модель |
| 8.1.10 | Выбор listener/transport, недоступные UDP/WSS/TLS и отсутствие fallback | 4 | Конфигурация, smoke-тесты |
| 8.1.11 | Request ID, forwarded/trace headers и безопасные логи | 4 | — |
| 8.1.12 | Graceful shutdown, deadlines и уникальность instance | 4 | SDK lifecycle, реестр |
| 8.1.13 | Неизменённые gorilla/coder WebSocket handlers, Hijacker и frames | 4 | QUIC internal CONNECT, WSS-модель |
| 8.1.14 | Handshake, Origin, subprotocol, отказ, private credentials и момент 101 | 4 | QUIC internal CONNECT, SDK codecs |
| 8.1.15 | Параллельные WS/HTTP/SSE, backpressure, 429 и слот после Hijack | 4 | WSS-модель |
| 8.1.16 | WS idle, write timeout, disconnect, drain и изоляция каналов | 4 | WSS-модель, SDK lifecycle |

### 8.2. Версии и канарейка

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.2.1 | Обнаружение версии, counters и отсутствие записи при отказе | 4 | Реестр |
| 8.2.2 | Конфигурация stable, 0% кандидата и отказ пустой версии | 4 | Реестр, SDK register |
| 8.2.3 | Доли 90/10 независимо от транспорта и числа реплик | 4 | Реестр |
| 8.2.4 | Границы весов, coverage и некорректные версии | 4 | Реестр, OpenAPI |
| 8.2.5 | Promote, previous stable и rollback | 4 | Реестр, OpenAPI |
| 8.2.6 | Недоступный canary даёт 503 без перераспределения | 4 | Реестр |
| 8.2.7 | Изменение политики сохраняет начатые HTTP/SSE/WS | 4 | — |
| 8.2.8 | Доступ к Admin API, аудит и метрики | 4 | OpenAPI |

### 8.3. Качество прототипа

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.3.1 | Go test/race/vet всех поставляемых модулей | 4 | Тесты текущих модулей |
| 8.3.2 | Coverage ≥70% и интеграция обоих транспортов | 4 | — |
| 8.3.3 | Compose с QUIC/WSS, SPA, canary, reports и тестовым CA | 4 | — |
| 8.3.4 | Health/readiness/metrics и ограниченная кардинальность | 4 | — |
| 8.3.5 | Воспроизводимый README, godoc, сценарии управления и оба WebSocket handler | 4 | — |
| 8.3.6 | Протокол, runbook, конфигурация, подписи и диагностика | 4 | Протокол, конфигурация, upstream |

### 8.4. Нагрузочная приёмка

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.4 | Цели §5.1 для QUIC/WSS/mixed, веса 90/10, большие тела и медленные потребители | 5 | — |

### 8.5. API-аутентификация, SPA и межсервисный доступ

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.5.1 | Public/private endpoint под одним префиксом | 4 | — |
| 8.5.2 | Очистка поддельных заголовков и защита пользовательского контекста | 4 | SDK HMAC profile |
| 8.5.3 | Делегирование A → B → C с ID, ролями и атрибутами | 4 | SDK HMAC profile |
| 8.5.4 | Отказ без подписи или политики до handler | 4 | SDK HMAC profile, OpenAPI |
| 8.5.5 | Подмена каждого подписанного компонента и binding | 4 | SDK HMAC profile |
| 8.5.6 | Ротация ключей и ограниченный replay cache | 4 | SDK replay interface |
| 8.5.7 | Streaming без чтения для подписи и повторной отправки | 4 | SDK HMAC profile, QUIC spike |
| 8.5.8 | Контекст SSE и WebSocket до handler, HMAC expiry handshake | 4 | SDK HMAC profile |
| 8.5.9 | SPA routes/assets, зарезервированное API и fallback | 4 | Реестр |

### 8.6. Монтирование

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.6.1 | Один бинарник, разные префиксы, preserve/strip | 4 | Контракт протокола |
| 8.6.2 | Точный mount, завершающий slash, алиасы, вложенные пути, границы сегментов, escaping и query | 4 | SDK пути, реестр |
| 8.6.3 | Подпись публичного path и mount до strip | 4 | SDK HMAC profile |
| 8.6.4 | SSE и неизменённые WebSocket handlers под обоими транспортами | 4 | QUIC spike частично |
| 8.6.5 | Location и остальные правила mount-header rewrite | 4 | — |
| 8.6.6 | Целостность URL в body/WS и примеры относительно mount | 4 | — |

### 8.7. Корневой frontend override

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.7.1 | Разрешение регистрации только назначенному frontend | 4 | Реестр |
| 8.7.2 | SPA и WebSocket до и после первой активации | 4 | Реестр |
| 8.7.3 | После потери активного frontend — 503 без fallback | 4 | Реестр |
| 8.7.4 | Canary и реплики только внутри назначенного service ID | 4 | Реестр |
| 8.7.5 | Отключение через YAML/restart или Admin API | 4 | Реестр, OpenAPI |
| 8.7.6 | Ошибочные ID, разрешения и shared root | 4 | Реестр, конфигурация |

### 8.8. Production security

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.8.1 | Fail-closed запуск, mTLS, grant, stores и security state | 5 | Конфигурация |
| 8.8.2 | Допуск экземпляров: token/cert/grant/binding, identity и generation | 5 | Credential fixtures |
| 8.8.3 | Revoke, bound deadlines и закрытие активных потоков | 5 | SDK lifecycle |
| 8.8.4 | Проверка issuer assertions, audience, claims и невозможность подделки ролей | 5 | SDK HMAC profile |
| 8.8.5 | Internal-only, отдельный listener и отказ для public identity | 5 | OpenAPI, конфигурация |
| 8.8.6 | Атомарный replay в конкуренции, при crash и recovery | 5 | SDK replay interface |
| 8.8.7 | Replay capacity и квоты при длительной нагрузке | 5 | — |
| 8.8.8 | TLS/Upgrade floods, slow clients, framing, credits и квоты | 5 | SDK codecs, WSS-модель |
| 8.8.9 | Публикация кандидата 0%, overlap и reserved prefixes | 5 | Реестр |
| 8.8.10 | Устойчивое состояние и защитные барьеры после crash/restart | 5 | — |
| 8.8.11 | Revoke/logout/expiry и сроки для SSE/WS | 5 | SDK lifecycle частично |
| 8.8.12 | Отрицательный HTTP/wire/HMAC corpus и parser ambiguity | 5 | SDK codecs, SDK HMAC profile |
| 8.8.13 | Browser boundary, cookie, CSP и Service Worker | 5 | — |
| 8.8.14 | Изоляция RBAC, scopes, preview и операции | 5 | OpenAPI |
| 8.8.15 | Supply chain, fuzz/race/integration, SBOM и эксплуатация | 5 | SBOM тестового модуля |

### 8.9. Active-passive

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.9.1 | Primary, резерв и переключение после отказа | 4 | Реестр |
| 8.9.2 | Not ready, callbacks, status timeout, drain и revoke | 4 | Реестр, SDK lifecycle |
| 8.9.3 | Preemption on/off и окно непрерывной готовности | 4 | Реестр |
| 8.9.4 | Исключение неподходящего instance/version/path/grant | 4 | Реестр |
| 8.9.5 | Canary выбирает версию, затем primary | 4 | Реестр |
| 8.9.6 | Потоки не мигрируют, POST не повторяется | 4 | — |
| 8.9.7 | Ручное переключение, RBAC, revision, аудит и UI | 4 | Реестр, OpenAPI |

### 8.10. Admin Web и редактор прав

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.10.1 | Management origin, cookies и изоляция от tunnel/frontend | 4 | Конфигурация BFF |
| 8.10.2 | OIDC Code/PKCE/state/nonce, callback и MFA | 4 | Конфигурация BFF |
| 8.10.3 | Отсутствие secrets/tokens в браузере | 4 | — |
| 8.10.4 | Viewer read/evaluate без мутаций | 4 | OpenAPI |
| 8.10.5 | Редактирование A → B, diff, правила и подтверждение | 4 | OpenAPI |
| 8.10.6 | Validate/evaluate/preview без change или dispatch | 4 | OpenAPI |
| 8.10.7 | Удаление/сужение политики блокирует запросы и активные потоки | 4 | — |
| 8.10.8 | Сбой транзакции/outbox, UI показывает исходную revision | 4 | — |
| 8.10.9 | Статусы transport, rollout, primary и зависимостей | 4 | — |

### 8.11. Платформы и встроенное хранилище

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.11.1 | Чистый нативный запуск Linux/Windows Server gateway, BFF и сервисов | 5 | QUIC spike на runners |
| 8.11.2 | Полный integration/security suite на обеих ОС | 5 | — |
| 8.11.3 | Windows Service lifecycle, recovery и Ctrl+C | 5 | — |
| 8.11.4 | Пути, ACL, firewall, PEM reload и OS lock | 5 | — |
| 8.11.5 | SQLite replay, квоты, commit faults, checkpoint и disk full | 5 | SQLite smoke |
| 8.11.6 | Сравнительный отчёт ОС × transport × backend | 5 | — |
| 8.11.7 | Отдельный Redis security/recovery suite при поставке адаптера | 5 | Условная конфигурация |

### 8.12. SQLite и PostgreSQL

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.12.1 | Общий контрактный набор control/replay/session для двух SQL backend | 5 | SQL smoke |
| 8.12.2 | Общий native suite для платформ и backend, включая Admin UI | 5 | — |
| 8.12.3 | PostgreSQL verify-full, CA, роли, schema version и durability | 5 | Проверка конфигурации клиента |
| 8.12.4 | Изоляция ролей и схем BFF/SDK/migration runtime | 5 | — |
| 8.12.5 | Lock, bootstrap, upgrade, backup/PITR, stale restore и primary switch | 5 | — |
| 8.12.6 | Offline SQLite ↔ PostgreSQL, сохранение security state и recovery | 5 | — |
| 8.12.7 | Нагрузочное сравнение backend с одинаковой durability | 5 | — |

### 8.13. Контракты для разработчиков

| Тест | Сценарий | Этап | Основа этапа 1 |
| --- | --- | --- | --- |
| 8.13.1 | Независимость, полный wire corpus, schemas, совместимость, fuzz и соответствие live Admin API | 1 и 4 | Контрактные проверки этапа 1, сверка live endpoints на этапе 4 |
| 8.13.2 | Конкурентный Run/Close/WaitReady, callbacks, panic и утечки | 4 | SDK lifecycle |
| 8.13.3 | Discovery B:api:/reports, mount/revision/grant/cache и явный refresh | 4 | Реестр, SDK HMAC profile |
| 8.13.4 | Problem Details, typed errors, API version, cursors и неизменный прикладной ответ | 4 | OpenAPI |
| 8.13.5 | Fault injection, atomic operation/outbox и idempotency | 4 | OpenAPI |
| 8.13.6 | RBAC/scope, revocation, bootstrap и recovery | 4 | OpenAPI, конфигурация |
| 8.13.7 | Static/rotating credentials, bindings, expiry/revoke и handover | 4 | Credential fixtures, SDK lifecycle |
| 8.13.8 | Управляемые таймауты HTTP/WS/DB/drain/barrier и reconnect | 4 | SDK lifecycle, WSS-модель |
| 8.13.9 | Retire/release/delete/purge, права, revision, ownership и tombstones | 4 | Реестр, OpenAPI |
| 8.13.10 | Отдельный boilerplate с released SDK, N/предыдущий minor, DB upgrade/restore и HTTP retry faults | 4 и 5 | Матрица совместимости |

## Трассировка требований

Разделы и подразделы ТЗ сгруппированы по соответствующим проверкам. Требования к опциональным расширениям этапа 6 (§7) проверяются при отдельном согласовании.

| Требования ТЗ | Сценарии приёмки |
| --- | --- |
| §1.2, §1.4, §2.1–2.2 | 8.1.*, 8.3.*, 8.5.*, 8.8.*, 8.10–8.12 |
| §2.3 | 8.13.1, 8.8.15 |
| §3.1 | 8.1.10, 8.8.1, 8.11.1–2 |
| §3.2 | 8.1.4–6, 8.8.2–3, 8.13.7, 8.13.10 |
| §3.3 | 8.1.2–5, 8.6.1–2, 8.7.*, 8.8.9, 8.13.9 |
| §3.4–3.5 | 8.2.*, 8.8.10, 8.9.5 |
| §3.6 | 8.1.1, 8.1.7–8, 8.1.11, 8.8.12, 8.13.4 |
| §3.7 | 8.1.6–9, 8.1.12, 8.13.2, 8.13.8, 8.13.10 |
| §3.8 | 8.1.11, 8.2.8, 8.3.4, 8.9.7, 8.10.9 |
| §3.9 | 8.2.*, 8.8.14, 8.13.4–6, 8.13.9 |
| §3.10 | 8.1.10, 8.3.2, 8.3.5, 8.6.1, 8.13.2–4, 8.13.7–8, 8.13.10 |
| §3.11 | 8.1.13–16, 8.5.8, 8.6.4, 8.7.2, 8.8.11 |
| §3.12–3.13 | 8.5.1–3, 8.5.9, 8.7.*, 8.8.4–5, 8.8.11, 8.8.13 |
| §3.14–3.15 | 8.5.2–8, 8.6.3, 8.8.4–8, 8.8.12, 8.13.3, 8.13.10 |
| §3.16 | 8.1.1, 8.6.*, 8.13.3 |
| §3.17 | 8.7.*, 8.8.9–10 |
| §3.18 | 8.9.*, 8.10.9 |
| §3.19–3.20 | 8.8.14, 8.10.*, 8.13.4–6 |
| §3.21 | 8.1.6, 8.1.12, 8.13.2, 8.13.8 |
| §3.22 | 8.6.1–3, 8.13.3 |
| §3.23–3.24 | 8.8.10, 8.8.14, 8.10.4–8, 8.13.4–6 |
| §3.25 | 8.8.2–3, 8.13.7 |
| §3.26 | 8.1.2, 8.8.9–10, 8.13.9 |
| §4.1 | 8.1.*, 8.5.2–7, 8.8.12, 8.13.1 |
| §4.2 | 8.13.1 (этап 1), 8.1.1, 8.1.6–8, 8.1.13–16 |
| §4.3 | 8.1.1, 8.1.6–9, 8.1.13–16, 8.13.1 |
| §4.4–4.5 | 8.1.5, 8.1.7–10, 8.1.13–16, 8.8.8, 8.8.12, 8.13.4 |
| §4.6 | 8.5.2–8, 8.6.3, 8.8.4–7, 8.8.12, 8.13.1 |
| §4.7 | 8.13.1, 8.13.10, 8.12.5–6 |
| §5.1–5.2 | 8.1.6–12, 8.1.15–16, 8.3.4, 8.4, 8.8.7, 8.9.*, 8.11.6, 8.12.7 |
| §5.3 | 8.5.2–8, 8.8.*, 8.10.1–4, 8.12.3 |
| §5.4–5.4.1 | 8.3.1, 8.11.*, 8.12.2, 8.13.10 |
| §5.5.1 | 8.8.1–3, 8.13.7 |
| §5.5.2 | 8.8.6–7, 8.8.10, 8.11.5, 8.12.1, 8.12.5–6, 8.13.5 |
| §5.5.3 | 8.5.4, 8.7.*, 8.8.5, 8.8.9, 8.13.9 |
| §5.5.4 | 8.5.2–3, 8.5.8, 8.8.4, 8.8.11 |
| §5.5.5 | 8.1.7–9, 8.1.15–16, 8.8.7–8, 8.8.12, 8.13.8 |
| §5.5.6 | 8.8.13–14, 8.10.*, 8.13.4–6 |
| §5.5.7 | 8.3.1, 8.3.6, 8.4, 8.8.15, 8.11.1–4, 8.11.6, 8.13.1 |
| §5.5.8 | 8.8.1, 8.8.6, 8.11.5, 8.11.7, 8.12.*, 8.13.10 |
| §5.6 | 8.1.7, 8.1.10, 8.1.12, 8.1.16, 8.5.7, 8.8.1, 8.8.3, 8.8.11, 8.9.2–3, 8.13.2, 8.13.8, 8.13.10 |
| §6 (базовая конфигурация), §6.1 | 8.1.10, 8.2.2, 8.3.3, 8.7.5–6, 8.8.*, 8.9.4, 8.13.1 |
| §6.2 | 8.8.13–14, 8.10.*, 8.13.1, 8.13.6 |
| §6.3–6.4 | 8.11.1–5, 8.11.7, 8.12.*, 8.13.1 |
| §6.5 | 8.3.3, 8.3.5–6, 8.8.14, 8.13.1, 8.13.6, 8.13.10 |
| §10.1–10.2 | 8.1.*, 8.3.5, 8.13.2 |
| §10.3 | 8.3.1–2, 8.8.15, 8.13.1, 8.13.10 |
| §10.4–10.7 | 8.5.*, 8.6.*, 8.7.* |
| §10.8–10.10 | 8.8.*, 8.9.*, 8.10.*, 8.13.6–7 |
