# Gateway QUIC transport boundary

`Accept` принимает существующий quic-go connection и обязательный `quiccontrol.Authorize`. Успешный bootstrap/ack подключает single-session reverse HTTP/3 из опубликованной закреплённой SDK revision. Gateway не использует local replace, соседний SDK checkout или go.work для сборки и tests.

`Session` предоставляет `http.RoundTripper`, `Send`/`Receive` для session control и `Done`/`Err`/`Close`. Request ID sanitization, bounded inflight, streaming/SSE, independent EOF и cancel реализует SDK `transport/quichttp`; автоматические dial/retry/redirect отсутствуют. CONNECT/virtual HTTP/1.1/Hijacker пока не подключены.

Authorizer обязан проверить transport identity, grant, permissions, expiry/revocation, конфликты и durable commit до ack. `Accept` сам не публикует маршруты и не устанавливает readiness. Вызывающий слой должен обработать status/commands через sessionstate, связать accepted handle с registry, проверять готовность/security перед каждым назначением и исключить session по Done/неудаче ack. Эти integration layers и durable backend ещё предстоит реализовать. SQL/RAM-подмена production допуска отсутствует.

Tests выполняют реальный mTLS bootstrap из опубликованного SDK, ordinary HTTP с точным Host/raw query и удалением внешнего transport ID, status/drain одновременно с HTTP и cleanup при закрытии carrier. Authorization callback синтетический; эти tests не означают production acceptance или работающий gateway executable.

## Привязка к registry и sessionstate

`AcceptBound` создаёт `BoundSession` поверх того же transport и модели `sessionstate.NativeStreams`. Обязательный `Admit` возвращает fresh registry Session, согласованный ack и проверенные SecurityReady/SecurityDeadline после внешних identity/grant/permissions/conflicts/durable checks. Callback сам отвечает за rollback своей неудачной admission transaction. Встроенного RAM production backend или автоматической положительной security readiness нет.

`Registry.BindTransport` однократно проверяет живой handle, instance/service/version/paths/mode/transport и начальное unready состояние. Ack должен совпасть с актуальными registry paths/states/revision. После успешного binding transport владеет локальным handle: отказ ack исключает эту session, сохраняя durable route ownership; ошибка повторного/чужого binding не удаляет уже существующий transport.

Перед включением назначений владелец публикует соответствие Handle → BoundSession и вызывает EnableDispatch. Даже немедленный ready-status до этого не выставляет registry readiness и не открывает dispatch; EnableDispatch также не активирует pending routes.

BoundSession единолично получает status. Только свежий монотонный status ready вместе с security readiness и завершённым ready_not_before даёт SetReady(true). Непроверенный ObservedAt не заменяет receiver time. Таймер default 100ms, допустимо 0…1s с 0 как default; он двигает freshness/security/credential deadlines и без трафика. SetSecurity немедленно снимает/восстанавливает gate; более ранний security deadline нельзя продлить. Revoke отменяет активный HTTP и закрывает connection.

RoundTrip требует предварительного авторизованного route selection; он повторно проверяет именно выбранный registry handle, не выбирает другой instance и не делает retry. NativeLease удерживается до completion обоих направлений через SDK RoundTripWithCompletion, а не до response headers/EOF. Неготовый или stale handle не отправляет HTTP. Pending route activation и stable/canary policy остаются в registry/control layer.

Close(ctx) завершает transport немедленно и ограничивает ожидание local cleanup контекстом. Done означает завершение reader/timer и освобождение native exchanges/registry handle. При upload reader, нарушающем net/http concurrent Close contract, ожидание может истечь, но старый instance остаётся занятым до реального completion; повторная регистрация не обходит cleanup. Удаляется только Session handle, не retained route ownership; stale handles не изменяют replacement.

Graceful drain/unregister/reconnect и ordered starts fence для native QUIC ещё не интегрированы. HTTP/3 requests и stream 0 имеют независимый delivery order: нельзя объявлять WSS writer fence рабочим QUIC fence. Получение таких команд в BoundSession сейчас закрывает connection fail-closed с ErrControlNotIntegrated, без фиктивного ack. Low-level Session остаётся доступен для отдельной реализации control layer. Virtual HTTP/1.1/Hijacker, service-side Client lifecycle и durable production admission остаются будущими шагами.
