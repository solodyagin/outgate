# Разработка сервиса: SDK и выдаваемый boilerplate

Статус: контракт поставки первой версии. Wire-основа SDK (`protocol/v1`) перенесена в отдельный [solodyagin/outgate-sdk](https://github.com/solodyagin/outgate-sdk), module path — `github.com/solodyagin/outgate-sdk` (см. [статус реализации](implementation-status.md)). Прикладной `outgateclient`, versioned SDK release, отдельный template repository и работающий gateway ещё отсутствуют. Этот документ не предлагает скачивать несуществующий release.

## 1. Что получает разработчик

Разработчик получает отдельный `outgate-service-template`, pinned release `outgate-sdk`, README и конфигурационный пример своего service_id. Код gateway, административные секреты, deployment-grant issuer и права управления политиками не передаются. Организация может ограничить доступ к gateway repository независимо от SDK/template. Шлюз запускается оператором; разработчик пользуется общим development stand либо проверяет свой handler локально.

Пакет подключения — `github.com/solodyagin/outgate-sdk/outgateclient`, module — `github.com/solodyagin/outgate-sdk`. После реализации `outgateclient` и публикации versioned SDK release dependency устанавливается обычным Go tooling:

```bash
go get github.com/solodyagin/outgate-sdk/outgateclient@v1.0.0
```

Это пример будущей release-команды, не наличие версии в registry. SDK version фиксируется в service go.mod/go.sum; приложение не импортирует gateway. Код SDK собирается вместе с сервисом, отдельного локального SDK process/sidecar нет. Названия Client/New/Run/Close/WithHandler и остальных options определены в requirements.md 3.10.

## 2. Контракт шаблона

Boilerplate — отдельный самодостаточный Go-проект, который копируют/generate один раз под новый сервис, а не dependency для бизнес-кода. Он использует released SDK без локального replace, обязательного go.work, git submodule или ссылки на рабочую копию gateway. После смены module/service name разработчик изменяет свои handlers/config/auth integrations и развивает repository самостоятельно.

Состав:

| Часть | Обязательное поведение |
| :--- | :--- |
| cmd/service | main/composition root; ошибки запуска, signals, Run/Close, bounded shutdown |
| internal/app | настройка outgateclient, запуск/ожидание состояния и dependency injection |
| internal/config | проверяемые service/instance/version, addresses, transport, paths/mounts, secret file references |
| internal/handlers | /hello, /health, /ready; обычный http.Handler с локальными URI |
| internal/auth | integration interfaces для собственной auth/authorization API; protected example deny-by-default |
| configs | local, development tunnel, production Linux/Windows examples, без реальных секретов |
| deploy | native Linux/Windows build/run и optional service hosting; никаких требований WSL/Docker для runtime |
| tests | handler/config/lifecycle tests и documented integration smoke с отдельным test gateway |
| README | команды, назначение параметров, permissions, диагностика и обновление SDK |

Template не включает реализацию QUIC/WSS/HMAC/replay verifier, SQL migrations gateway или копию SDK: это ответственность SDK/gateway. Пользовательская БД/бизнес-логика сервиса не смешиваются с SDK replay DB. Replay backend может быть локальной SQLite независимо от gateway PostgreSQL.

## 3. Три режима запуска

- `local`: только explicit local mode, обычный HTTP server на 127.0.0.1:8080, для проверки тех же handlers без SDK connection, gateway, grant или replay store. Этот режим не имитирует trusted CallerService/UserContext, не создаёт фиктивного пользователя и не допускается как публичный production launch. Protected sample возвращает 401 без настроенной собственной auth.
- `development`: SDK соединяется с отдельным test gateway, `WithSecurityMode("development")` задаётся явно. TLS server certificate проверяется, development token выдаётся оператором; код по-прежнему не хранит его. Общий gateway стенд не требует выдавать его repository разработчику.
- `production` (default): только SDK tunnel, без публичного HTTP listener сервиса; mTLS/grant/issuer/replay/revocation настройки обязательны. Отсутствующий параметр вызывает ошибку, а не local/development fallback. Diagnostics listener выключен по умолчанию, при явном включении loopback-only с отдельной политикой; /health в прикладном mux не заменяет SDK local readiness callback.

Режим приложения — `SERVICE_MODE`, значения local/development/production. Общие connection и identity settings: OUTGATE_GATEWAY_ADDR, OUTGATE_SERVICE_GATEWAY_URL (отдельный HTTPS service origin), OUTGATE_SERVICE_ID, OUTGATE_INSTANCE_ID, OUTGATE_SERVICE_VERSION, OUTGATE_TRANSPORT, OUTGATE_SERVICE_PATHS, OUTGATE_MOUNTS, OUTGATE_SECURITY_CONFIG. OUTGATE_SERVICE_PATHS — список comma-separated paths; OUTGATE_MOUNTS — JSON object mount_id → prefix. В production identity/paths/mounts должны точно совпадать с выданным grant/certificate и разрешениями gateway; template не расширяет их сам. Windows/Linux secret paths задаются config, а не зашиваются в handlers. Token/private key не передаются CLI flags и не попадают в logs.

## 4. Handler не знает production mount

Прикладной mux регистрирует `/hello` и `/reports`, а app composition включает `WithStripPrefix(true)` и deployment-configured paths/mounts. Например, один и тот же `/hello` доступен как /api/v1/hello или /partners/reports/hello после разрешённого перемонтирования без изменения handler. SDK проверяет подписи до strip; request context содержит MountInfo для диагностики/генерации ссылок, но не считается пользовательским полномочием.

Публичный mount — решение оператора; разработчик не задаёт root `/`, shared path или канареечную долю самостоятельно. Для обращения к другому сервису применяется SDK NewServiceRequest + ServiceHTTPClient по target service/mount/local URI, а не зашитый чужой production prefix. Прямой публичный URL тоже поддерживается при явной конфигурации. Production user delegation требует issuer assertion: local UserContext и произвольные X-User-* не являются доказательством identity.

## 5. Запуск и остановка

Порядок production host: parse/validate config → открыть собственные зависимости → создать handlers/auth middleware → создать outgateclient → запустить Run → отслеживать WaitReady/Status → обслуживать приложение через tunnel. Приложение не ждёт ready до запуска Run. Startup barrier и waiting credentials показываются как initializing, не как успешная готовность. Для active-passive template передаёт WithReadinessCheck с проверкой только обязательных локальных dependencies; standby не выключает ready.

Ctrl+C/служебная остановка запрещают новые операции и вызывают SDK Close с 30s deadline. Handler и callbacks обязаны учитывать context cancellation. Установка Windows Service требует OS privileges, штатный runtime — отдельного ограниченного account; никакого LocalSystem по умолчанию. Незавершённые WS/SSE не мигрируют; gateway/SDK сами выполняют bounded drain, приложение не воспроизводит POST на другом instance. Нормальные бизнес-ошибки остаются у handler, transport ошибки разбираются через typed SDK Error.

## 6. Что настраивает оператор

Оператор заранее создаёт service identity/allowed paths/mount permissions, выдаёт certificate и ограниченный grant, задаёт policies caller→target и user/background delegation, выбирает rollout/active-passive и выделяет тестовый endpoint. Разработчик получает только credentials своего instance и config references, не service/admin CA private keys или global HMAC keyrings. SDK rotation provider обновляет согласованную cert/grant пару через разрешённый deployment process; boilerplate не выпускает grants самостоятельно.

Примеры token/assertion flow документируются с mock issuer только для test stand. Template не реализует встроенную production password database и не подменяет API authentication gateway role headers. В local mode межсервисный trusted call недоступен без явно настроенного SDK development/production connection.

## 7. Приёмка boilerplate

1. Чистый checkout шаблона после документированной смены module/service name собирается с GOWORK=off на Linux amd64 и Windows amd64; используются опубликованные pinned SDK версии, не локальные gateway/SDK directories.
2. Local /hello/health/ready и protected 401 проходят без gateway/replay store; production без credentials не запускается и не включает local HTTP listener. Local/development выбираются явно, не через отсутствие secrets.
3. Один handler обслуживается под двумя разрешёнными mount prefixes без правок исходников. SDK connection проверен отдельно для QUIC/WSS, readiness, graceful close и no-retry поведения; шаблон не содержит transport implementation.
4. Производится code/dependency review: в прикладном repository нет gateway/admin UI/outbox/control migrations/reverst, секретов и абсолютных путей разработчика; SDK не импортирует gateway.
5. README содержит первые шаги, local/tunnel команды, получение credentials у оператора, Windows/Linux run/build, типовые auth/path/UDP ошибки и пример обновления SDK с проверкой compatibility matrix. Любой hook auth объяснён и deny-by-default, а не оставлен как безопасно выглядящий allow-all TODO.
6. Разработчик может развивать созданный сервис независимо от версии boilerplate. Обновления runtime получают через versioned SDK; обновление шаблона не переписывает бизнес-код автоматически. Релиз SDK проверяется на реальном downstream test service вне его repository.
