# Правила разработки Outgate

## Источники и порядок работы

- Перед изменениями читайте относящиеся к задаче разделы `docs/requirements.md`, `docs/protocol.md` и `docs/protocol.schema.json`. Требования production имеют приоритет над development-упрощениями.
- Реализуйте проверяемые части этапов из раздела 7 ТЗ. В `../project-notes/implementation-status.md` указывайте фактически выполненное и оставшиеся проверки; каркас или unit tests не означают завершённую приёмку.
- Перед продолжением работы читайте раздел «Точка продолжения» в `../project-notes/implementation-status.md` и сверяйте его с текущим кодом и рабочим деревом Git. После каждого завершённого шага и перед остановкой обновляйте этот раздел: текущая задача, завершённые шаги, незавершённая работа, выполненные проверки, блокеры и конкретное следующее действие. Отличайте проверки текущей сессии от ранее записанных результатов; подробности реализации и приёмки оставляйте в существующих разделах без дублирования. Отдельный changelog для точки продолжения не создавайте.
- Общий статус и точка продолжения — локальные заметки workspace в `../project-notes/implementation-status.md` (путь от корня checkout), вне Git-репозиториев компонентов. Обновляйте один общий файл для gateway, SDK и service-template; не дублируйте его в репозиториях и не включайте в коммиты компонентов. Если файла нет на другой машине, сообщите об этом и восстановите контекст по коду и Git; не создавайте статус внутри компонента.
- Изменение wire-контракта требует синхронного обновления ТЗ, protocol/schema, golden fixtures и тестов. Не меняйте нормативные fixtures только ради прохождения реализации.
- Не публикуйте реальные домашние каталоги, персональные пути и расположение локальных резервных копий, включая документы, отчёты проверок и сообщения коммитов. Используйте относительные пути, ссылки на repositories и явные нейтральные placeholders (`<user>`, `${USER}`, `<temporary-directory>`). Конкретные временные пути заменяйте описанием назначения файла; системные пути и переносимые примеры команд допустимы.

## Границы архитектуры

- Код самостоятельный. Запрещены reverst imports, транзитивные зависимости, vendoring, копирование/адаптация исходников и запуск reverst как обязательного инструмента.
- Конечная поставка: отдельные gateway, SDK и service-template repositories/modules (ТЗ 10.3). SDK находится в отдельном repository `https://github.com/solodyagin/outgate-sdk` (module `github.com/solodyagin/outgate-sdk`); локальный checkout может располагаться рядом с gateway в `../outgate-sdk/`. Шаблон сервиса имеет отдельный repository `https://github.com/solodyagin/outgate-service-template` (локально, например `../outgate-service-template/`); repository содержит README, готового boilerplate нет. Вложенных SDK и service-template в этом repository нет. Не создавайте фиктивные remote repositories/releases.
- SDK не импортирует gateway; `protocol/v1` содержит только wire types/codecs/чистые helpers. SQL, sockets, RBAC и административный код сюда не входят. Не дублируйте wire definitions в gateway.
- Не начинайте QUIC adapter до сквозного spike напрямую на quic-go с reverse HTTP/3, stream 0 exclusion, streaming/cancel, internal CONNECT и проверкой Linux/Windows. Не подменяйте HTTP/3 самодельным framing поверх QUIC.

## Инварианты

- Production по умолчанию, fail closed. Никаких автоматических transport/security fallback, InsecureSkipVerify, фиктивных identity и логирования credentials.
- Ограничивайте размеры до выделения памяти. Не буферизуйте целиком HTTP body. После начала передачи запроса business retry запрещён для любого метода.
- Нормализация префиксов и однократное декодирование URI различаются. Не применяйте path.Clean и повторный decode. Известный недоступный маршрут не уходит в SPA fallback.
- При добавлении зависимости фиксируйте версию, проверяйте совместимость и безопасность, лицензии и SBOM. Не выбирайте версии по историческому go.mod архитектурного референса.

## Проверка

- Из корня: `python3 tests/fixtures/protocol/v1/verify.py`.
- Gateway transport/dependencies: `GOWORK=off go mod verify`, `python3 -B tests/verify_sbom.py`, `GOWORK=off go test -race ./...`, `GOWORK=off go vet ./...`; Windows build/test compile проверяйте отдельно. SDK revision и compiled test inventory должны совпадать с закреплённым module graph, без local replace.
- Проверка домашних путей в отслеживаемых текстовых файлах: `python3 -B tests/check_local_paths.py`; её тесты: `python3 -B -m unittest discover -s tests -p 'test_check_local_paths.py'`. Проверка выполняется в CI на Linux/Windows, читает рабочие версии файлов из `git ls-files` и сообщает только файл/строку. Новые файлы охватываются после добавления в Git. Это проверка распространённых форм домашних путей, не универсальный поиск персональных данных или проверка истории Git; прочие персональные и временные пути проверяйте при review.
- SDK (из отдельного checkout, например `../outgate-sdk/`): `GOWORK=off go test -race ./...` и `GOWORK=off go vet ./...`.
- Для protocol/parser изменений добавляйте негативные и граничные тесты, сверку существующих golden bytes и при необходимости fuzz targets.
- Проверяйте Windows compile отдельно; cross-compile не объявляйте native Windows runtime-проверкой.
- Не создавайте обязательный go.work/локальные replace в публикуемых модулях. Команды без сети должны работать без registry для частей, использующих только standard library.

## Локальные скилы

- [commit](.agents/skills/commit/SKILL.md) — подготовка сообщений и создание Git-коммитов по Conventional Commits с проверками Outgate.

При использовании прочитайте `SKILL.md` и указанные в нём правила именования.
