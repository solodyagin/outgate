# Сквозная проверка reverse HTTP/3

Проверка относится к ТЗ §2.3 и [протоколу §5](protocol.md#5-quic-reverse-http3-transport). Тесты используют Go 1.27.4, закреплённый `quic-go v0.65.0` и `protocol/v1` SDK из [тестового модуля](../tests/dependencies/go.mod). Два QUIC-участника работают на временном loopback-сокете и доверяют сертификату текущего теста. Для register и ack используются имеющиеся golden fixtures. [Код spike](../tests/dependencies/quic_reverse_test.go).

| Проверка | Наблюдение на Linux amd64 |
| --- | --- |
| TLS и регистрация | TLS 1.3, частный ALPN `outgate-tunnel/1`, handshake без 0-RTT. Сервис открывает bidi stream 0. Gateway считывает bootstrap и register на этом потоке и отправляет ack до запуска HTTP/3. |
| Обратное направление | Gateway создаёт HTTP/3 клиент поверх принятого QUIC-соединения через `Transport.NewClientConn`. Сервис передаёт своё исходящее соединение в `Server.ServeQUICConn`. Bootstrap остаётся доступен после SETTINGS. Gateway открывает CONNECT на bidi streams 1, 5 и 9. |
| HEADERS и потоковый HTTP | Сохраняются Host, escaped path, исходный query, повторные заголовки запроса и `Set-Cookie`. Клиент получает первый SSE flush до окончания upload. Stream 0 продолжает передавать status и drain. |
| Отмена запроса | Отмена контекста прерывает незавершённый upload с `H3_REQUEST_CANCELLED` (`0x10c`) и отменяет контекст handler. Одновременный SSE-запрос завершается, а на том же соединении проходит следующий HTTP-запрос. |
| Внутренний CONNECT | `OpenRequestStream` и `HTTPStreamer.HTTPStream` передают двунаправленные DATA с обычным CONNECT к `outgate-app-channel.invalid:443`. Другой authority отклоняется. После транспортного 200 тестовый HTTP/1.1 peer возвращает вложенный 101 либо 403. Маскированный и немаскированный WebSocket-кадры сохраняются побайтово; после FIN загрузки ответное направление остаётся доступным. |

На стороне сервиса stream 0 открыт локально. `ServeQUICConn` принимает удалённые двунаправленные потоки, поэтому этот поток остаётся у регистрационного кода. Библиотека ведёт HTTP/3 SETTINGS и кодирование заголовков. Тест использует публичные API для обоих направлений. При отмене код `0x10c` доступен в ошибке чтения тела, а `Request.Context` сообщает `context.Canceled`. Для успешного CONNECT тест сначала читает внешний 200, затем отдельно разбирает вложенный HTTP/1.1 ответ. [API HTTP/3](https://pkg.go.dev/github.com/quic-go/quic-go@v0.65.0/http3).

На Linux amd64 оба сценария прошли по 100 прогонов и по 20 прогонов с race detector. Тестовый бинарник собран для Windows amd64 при `CGO_ENABLED=0`. Нативный Windows-прогон остаётся условием завершения проверки перед этапом 2. Windows job запускает эти тесты в обычной матрице gateway после публикации изменений.

## Воспроизведение

Из `tests/dependencies` на Linux выполните:

```bash
GOWORK=off CGO_ENABLED=0 go test -mod=readonly -v -run '^TestQUICReverse' -count=1 ./...
```

В PowerShell задайте `$env:GOWORK = 'off'` и `$env:CGO_ENABLED = '0'`, затем выполните `go test -mod=readonly -v -run '^TestQUICReverse' -count=1 ./...`.

Тест использует синтетический development credential и тестового HTTP/1.1 peer. Интеграция с gateway/SDK, virtual listener и Hijacker, production identity, наблюдаемость и эксплуатационные лимиты относятся к реализации адаптера.
