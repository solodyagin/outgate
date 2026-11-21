# Outgate — Reverse API Gateway

Репозиторий: [solodyagin/outgate](https://github.com/solodyagin/outgate). Реализация [технического задания](docs/requirements.md). Начат этап 1; работающего шлюза и versioned SDK release пока нет.

- `docs/` — нормативные требования, протокол и [статус реализации](docs/implementation-status.md).
- `tests/fixtures/protocol/v1/` — нормативный golden corpus.
- [outgate-sdk](https://github.com/solodyagin/outgate-sdk) — отдельный Go-модуль `github.com/solodyagin/outgate-sdk`, сейчас только чистый пакет `protocol/v1`.
- [outgate-service-template](https://github.com/solodyagin/outgate-service-template) — отдельный репозиторий шаблона сервиса; пока пуст, реализация boilerplate ещё не начата.

Конечная поставка разделена на gateway, SDK и service-template repositories. SDK вынесен из этого repository; репозиторий service-template создан отдельно. Сам шаблон и versioned releases ещё отсутствуют. Прикладной `outgateclient` и transport adapters ещё не реализованы. Локальных `replace` и обязательного `go.work` нет.

## Проверка

Из корня gateway, Python 3.12+:

```bash
python3 tests/fixtures/protocol/v1/verify.py
```

В Windows используется `python` вместо `python3`. CI gateway проверяет нормативный corpus; Linux/Windows Go-проверки находятся в отдельном SDK repository. Команды SDK — в его [README](https://github.com/solodyagin/outgate-sdk#readme).

SDK содержит локальный snapshot schema/fixtures, поэтому собирается и тестируется без gateway checkout. При изменении wire-контракта обновляйте ТЗ, protocol/schema, fixtures и SDK согласованно. Для соседних checkout побайтовая сверка из gateway:

```bash
cmp docs/protocol.schema.json ../outgate-sdk/docs/protocol.schema.json
diff -r tests/fixtures/protocol/v1 ../outgate-sdk/tests/fixtures/protocol/v1
```

Происхождение и порядок обновления snapshot описаны в SDK: `docs/contract-snapshot.md`.
