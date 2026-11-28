# Outgate — Reverse API Gateway

Outgate — обратный API gateway для Go-сервисов. Сервисам не нужно публиковать входящий порт: они устанавливают исходящее защищённое соединение к шлюзу, а внешние клиенты обращаются к одному домену через обычный HTTPS.

Шлюз маршрутизирует запросы к зарегистрированным префиксам, сохраняет потоковую передачу и поддерживает discovery mount points, канареечное распределение, active-passive реплики и отдельную административную плоскость. Для транспортного подключения доступны QUIC/HTTP/3 и WSS.

> Проект находится в процессе реализации. Наличие отдельных модулей и контрактов не означает, что весь gateway готов к production-развёртыванию. Перед использованием сверяйтесь с [матрицей приёмки](docs/acceptance-matrix.md) и актуальным статусом разработки, если он доступен.

## Как это работает

```text
Внешний HTTPS-клиент ──► Outgate gateway
                            │
                            ├── QUIC/HTTP/3 туннель ──► экземпляр сервиса
                            └── WSS туннель         ──► экземпляр сервиса
```

Типовой сценарий:

1. Сервис настраивает SDK и устанавливает исходящее соединение.
2. Сервис регистрирует разрешённые URL-префиксы, версию и instance ID.
3. Gateway проверяет права и регистрирует экземпляр.
4. Внешний HTTP-запрос сопоставляется с наиболее подходящим префиксом.
5. Gateway выбирает версию и экземпляр и передаёт запрос через транспортный туннель.

Неизвестный путь под зарезервированным префиксом `/api` не отправляется в SPA fallback. Для остальных маршрутов используется настроенный SPA-upstream или frontend tunnel, если он разрешён и активирован.

## Возможности проекта

- Регистрация сервисов и маршрутизация по URL-префиксам.
- Исходящие транспортные соединения QUIC/HTTP/3 и WSS.
- Round-robin и active-passive для реплик; stable/canary rollout.
- Потоковая передача HTTP, SSE и WebSocket.
- Discovery логических mount points и настройка strip/preserve пути.
- Подписанные межсервисные HTTPS-вызовы и проверка политик доступа.
- Отдельные контракты для gateway, SDK и шаблона сервиса.
- Admin API, схемы конфигурации и durable control-state компоненты.

## Компоненты

Проект разделён на три отдельных репозитория:

| Компонент | Назначение | Ссылка |
|---|---|---|
| Gateway | Маршрутизация, транспортные адаптеры, control state и административные контракты | Этот репозиторий |
| SDK | Клиентская Go-библиотека и wire types/codecs протокола | [outgate-sdk](https://github.com/solodyagin/outgate-sdk) |
| Service template | Стартовый шаблон сервиса, подключаемого к gateway | [outgate-service-template](https://github.com/solodyagin/outgate-service-template) |

## Навигация по репозиторию

- [`docs/`](docs/) — требования, протоколы, схемы и контракты.
- [`docs/context-map.md`](docs/context-map.md) — карта проекта для разработки: с неё удобно начинать работу над задачей.
- [`docs/requirements.md`](docs/requirements.md) — техническое задание.
- [`docs/protocol.md`](docs/protocol.md) и [`docs/protocol.schema.json`](docs/protocol.schema.json) — wire-контракт протокола v1.
- [`docs/admin-openapi.yaml`](docs/admin-openapi.yaml) — спецификация Admin API в OpenAPI 3.1.
- [`docs/config.schema.json`](docs/config.schema.json) и [`docs/admin-web.schema.json`](docs/admin-web.schema.json) — схемы конфигурации gateway и Admin Web/BFF.
- [`docs/credentials.md`](docs/credentials.md) — deployment grants и ротация credentials.
- [`docs/dependencies.md`](docs/dependencies.md) — зависимости и команды их проверки.
- [`docs/compatibility.md`](docs/compatibility.md) и [`docs/acceptance-matrix.md`](docs/acceptance-matrix.md) — совместимость и критерии приёмки.
- [`tests/fixtures/protocol/v1/`](tests/fixtures/protocol/v1/) — golden corpus протокола.
- [`internal/registry/`](internal/registry/) — реестр маршрутов, версий и экземпляров.
- [`internal/transport/quictunnel/`](internal/transport/quictunnel/) — QUIC-транспорт и admission lifecycle.
- [`internal/servicecall/`](internal/servicecall/) — service mTLS listener для подписанных вызовов.
- [`internal/controlstate/`](internal/controlstate/) — durable control state и регистрация.

## Для разработчиков

Перед изменением прочитайте [карту контекста](docs/context-map.md), затем связанные с задачей разделы требований и протокола. Обязательные и платформенные проверки перечислены в [docs/checks.md](docs/checks.md).

### Требования

- Go toolchain, указанный проектом в `go.mod`.
- Python 3.12+ для contract validators.
- Подходящий C toolchain для race detector на Linux.

### Быстрые проверки

Из корня репозитория:

```bash
python3 -B tests/check.py package ./internal/registry
python3 -B tests/check.py contracts
python3 -B tests/check.py full
python3 -B tests/check.py full --plan
```

В Windows используйте `python` вместо `python3`. Команда `full --plan` показывает набор команд без их выполнения.

Для прямого запуска ключевых contract и Go-проверок:

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

На Windows перед Go-командами задайте `$env:GOWORK = 'off'`; race-тесты и проверку Windows-сборки выполняйте согласно [docs/checks.md](docs/checks.md).

## Безопасность и границы гарантий

Production-развёртывание требует полного соответствия техническому заданию и критериям приёмки: в частности, корректной настройки TLS/mTLS, credentials, durable state, сетевых ограничений и административного доступа. Development-конфигурация не является готовым production-профилем.

Подробности и актуальные нормативные требования находятся в [техническом задании](docs/requirements.md), [контракте credentials](docs/credentials.md) и [матрице приёмки](docs/acceptance-matrix.md).

## Лицензия

MIT. См. [LICENSE](LICENSE).
