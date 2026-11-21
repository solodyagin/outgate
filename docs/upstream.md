# Архитектурные референсы и независимость реализации

## 1. Решение Outgate

Outgate реализуется самостоятельно по [requirements.md](requirements.md), п. 2.3, и [protocol.md](protocol.md). Импорт модулей/пакетов reverst, его транзитивное включение, vendoring, копирование/переработка кода и fork запрещены. Для сборки, тестов, установки и работы Outgate не нужны исходники или запущенные бинарники reverst.

Для QUIC/HTTP3 используются напрямую независимые quic-go/http3 API; для WSS — независимая WebSocket-библиотека. Такие библиотеки разрешены и имеют собственные лицензии/версии; одинаковая зависимость у двух проектов не делает один проект зависимым от другого. Собственные transport adapters, управляющий протокол, SDK, routing/auth/rollout и Admin API принадлежат реализации Outgate.

Историческое имя этого файла сохранено для существующих ссылок. Он не является списком runtime/build dependencies и не требует адаптации upstream. Фактические зависимости фиксируются в module graph/lock, license inventory и SBOM реализации.

## 2. Рассмотренный референс reverst

| Поле | Значение |
| :--- | :--- |
| Repository | https://github.com/flipt-io/reverst |
| Рассмотренная source revision | `079254f5f537d00b5ba6d0540897a5e922fb142e` |
| Commit timestamp | 2025-01-10T22:55:02Z |
| Дата изучения | 2026-11-21 |
| Архивный текст лицензии референса | [references/reverst-LICENSE](references/reverst-LICENSE), Apache-2.0 |
| Назначение | История архитектурного анализа; не baseline для fork/dependency |

Ревизия получена из GitHub API, исходники рассмотрены по immutable SHA. В репозитории Outgate не размещены эти исходники. Архивная лицензия референса не означает его inclusion в бинарник или SBOM; она перенесена из third_party в docs/references, чтобы не обозначать несуществующий vendored dependency.

Рассмотрены:

- [pkg/protocol/protocol.go](https://github.com/flipt-io/reverst/blob/079254f5f537d00b5ba6d0540897a5e922fb142e/pkg/protocol/protocol.go): отдельная регистрация с MessagePack и upstream ALPN quic-h3-tunnel.
- [client/client.go](https://github.com/flipt-io/reverst/blob/079254f5f537d00b5ba6d0540897a5e922fb142e/client/client.go): сервис инициирует QUIC, регистрируется, затем обслуживает reverse HTTP/3 на существующем connection.
- [internal/server/server.go](https://github.com/flipt-io/reverst/blob/079254f5f537d00b5ba6d0540897a5e922fb142e/internal/server/server.go): gateway принимает регистрацию и использует connection для reverse HTTP/3.
- [go.mod](https://github.com/flipt-io/reverst/blob/079254f5f537d00b5ba6d0540897a5e922fb142e/go.mod): исторические Go/quic-go версии этого проекта не задают версии Outgate.

От собственного Outgate протокола не требуется compatibility с reverst: ALPN outgate-tunnel/1, bounded control stream, JSON codec, регистрация mounts/identity и остальные возможности определены собственным контрактом. Рассмотрение чужого кода не считается разрешением копировать его в Outgate под другим именем; соблюдение этого решения проверяется review.

## 3. Проверки собственной реализации

Перед этапом 2 обязательны собственный spike напрямую на выбранной quic-go, корректность control stream/reverse HTTP3/QPACK, streaming/cancel/internal CONNECT WebSocket и нативный запуск Linux/Windows. Запуск upstream tests/example не является gate и не заменяет проверки Outgate.

Если публичные API выбранной библиотеки несовместимы с Draft reverse mapping, сначала пересматриваются ADR/requirements/protocol/schema/fixtures. Добавлять reverst или называть произвольный framing поверх QUIC стандартным HTTP/3 запрещено. Реальное выполнение spike пока не подтверждено; protocol fixtures проверяют кодирование, не сетевую совместимость.

До релиза CI проверяет resolved module graph/imports/vendor/SBOM на отсутствие reverst, а review — происхождение собственного кода. Версии реальных библиотек фиксируются после compatibility/security проверки; их лицензии и уведомления включаются по применимым условиям. Сторонние QUIC/TLS/SQL реализации не переписываются с нуля только ради формального отсутствия dependencies.
