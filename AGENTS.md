# Правила разработки Outgate

## Источники и порядок работы

- Перед изменениями читайте относящиеся к задаче разделы `docs/requirements.md`, `docs/protocol.md` и `docs/protocol.schema.json`. Требования production имеют приоритет над development-упрощениями.
- Реализуйте проверяемые части этапов из раздела 7 ТЗ. В `docs/implementation-status.md` указывайте фактически выполненное и оставшиеся проверки; каркас или unit tests не означают завершённую приёмку.
- Изменение wire-контракта требует синхронного обновления ТЗ, protocol/schema, golden fixtures и тестов. Не меняйте нормативные fixtures только ради прохождения реализации.

## Границы архитектуры

- Код самостоятельный. Запрещены reverst imports, транзитивные зависимости, vendoring, копирование/адаптация исходников и запуск reverst как обязательного инструмента.
- Конечная поставка: отдельные gateway, SDK и service-template repositories/modules (ТЗ 10.3). Пока SDK разрабатывается в `outgate-sdk/` как самостоятельный модуль для последующего выделения. Не создавайте фиктивные remote repositories/releases.
- SDK не импортирует gateway; `protocol/v1` содержит только wire types/codecs/чистые helpers. SQL, sockets, RBAC и административный код сюда не входят. Не дублируйте wire definitions в gateway.
- Не начинайте QUIC adapter до сквозного spike напрямую на quic-go с reverse HTTP/3, stream 0 exclusion, streaming/cancel, internal CONNECT и проверкой Linux/Windows. Не подменяйте HTTP/3 самодельным framing поверх QUIC.

## Инварианты

- Production по умолчанию, fail closed. Никаких автоматических transport/security fallback, InsecureSkipVerify, фиктивных identity и логирования credentials.
- Ограничивайте размеры до выделения памяти. Не буферизуйте целиком HTTP body. После начала передачи запроса business retry запрещён для любого метода.
- Нормализация префиксов и однократное декодирование URI различаются. Не применяйте path.Clean и повторный decode. Известный недоступный маршрут не уходит в SPA fallback.
- При добавлении зависимости фиксируйте версию, проверяйте совместимость и безопасность, лицензии и SBOM. Не выбирайте версии по историческому go.mod архитектурного референса.

## Проверка

- Из корня: `python3 tests/fixtures/protocol/v1/verify.py`.
- SDK: `cd outgate-sdk && GOWORK=off go test -race ./...` и `GOWORK=off go vet ./...`.
- Для protocol/parser изменений добавляйте негативные и граничные тесты, сверку существующих golden bytes и при необходимости fuzz targets.
- Проверяйте Windows compile отдельно; cross-compile не объявляйте native Windows runtime-проверкой.
- Не создавайте обязательный go.work/локальные replace в публикуемых модулях. Команды без сети должны работать без registry для частей, использующих только standard library.
