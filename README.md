# Outgate — Reverse API Gateway

Реализация [технического задания](docs/requirements.md). Работа начата с wire-основы этапа 1; работающего шлюза и публичного SDK release пока нет.

- `docs/` — нормативные требования, протокол и [статус реализации](docs/implementation-status.md).
- `outgate-sdk/` — самостоятельный Go-модуль SDK, пока только чистый пакет `protocol/v1`.
- `tests/fixtures/protocol/v1/` — исходный golden corpus.

По ТЗ конечная поставка разделяется на три репозитория: gateway, SDK и service-template. Пока исходники SDK расположены здесь для начальной разработки; `github.com/yourorg/outgate-sdk` — явно неопубликованный placeholder. Локальных `replace` и обязательного `go.work` нет.

## Проверка

Нужны Go 1.27.4 и Python 3.12+. Сторонних Go-зависимостей пока нет; `go.sum` не требуется. Эти проверки не запускают сетевые слушатели.

Из корня, Linux:

```bash
python3 tests/fixtures/protocol/v1/verify.py
cd outgate-sdk
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
```

Windows PowerShell:

```powershell
python tests/fixtures/protocol/v1/verify.py
Set-Location outgate-sdk
$env:GOWORK = 'off'
go test ./...
go vet ./...
```

Фаззинг парсеров из `outgate-sdk/`:

```bash
go test ./protocol/v1 -run='^$' -fuzz=FuzzDecodeChunk -fuzztime=10s
go test ./protocol/v1 -run='^$' -fuzz=FuzzControlJSON -fuzztime=10s
```

Тесты SDK читают нормативные fixtures из родительской директории. Перед выделением SDK в отдельный repository потребуется упаковать snapshot контракта; сборка самого Go-пакета от этих файлов не зависит.
