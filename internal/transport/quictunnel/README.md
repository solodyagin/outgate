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

## Graceful drain (minor 1)

При negotiated required capability quic_quiescent_fence BoundSession поддерживает S-origin drain/drain_ack/unregister и G-origin Drain(ctx). Admission/ID allocation останавливаются немедленно; writer ждёт NativeActive=0, затем отправляет canonical frozen logical request-ID watermark. Частично завершённый HTTP/upload удерживает lease; deadline/revoke прерывает ожидание и не создаёт fake ack. Control queue ограничена MaxCommands и имеет одного writer; receiver/timer не блокируются на сетевой записи.

SDK `transport/quicsession.Service` проверяет G marker/command ledger, закрывает admission через HTTP Fence, ждёт actual handler cleanup, подтверждает G-origin drain и отправляет unregister. Reader продолжает принимать встречные команды; unregister дополнительно ждёт actual readiness invocation. После unregister_ack закрывает carrier нормально. Gateway исключает session из dispatch/подтверждает native cleanup до ack и сохраняет carrier, занятый instance ID и tunnel quota до нормального peer close в пределах оставшегося deadline. Close(ctx) по-прежнему немедленный, Drain(ctx) ожидает полную graceful последовательность.

Crossed уже переданные drain требуют обоих ack. Ещё не отправленный local drain intent присоединяется к peer drain; повторный Drain только сокращает deadline. Pending routes/ownership не удаляются. Без negotiated capability (включая minor 0) входящие native graceful команды закрывают connection fail-closed, а локальный Drain возвращает ErrControlNotIntegrated без смены transport/security режима.

Service-side control driver реализован в SDK; public `client.Client` предоставляет lifecycle/Close/security gate и sequential reconnect через внешний Connect callback. Встроенный QUIC credential/dial adapter поддерживает static/callback snapshots; file provider/proactive renewal, ServiceHTTPClient, internal CONNECT/virtual HTTP/1.1/Hijacker и production durable admission остаются следующими этапами. Низкоуровневые Session/SDK primitives не подменяют эти части фиктивной production identity.

Сквозные `TestServiceDriver*` запускают actual drivers обеих сторон из опубликованной exact SDK revision: readiness changes/security recovery, G/S/crossed drain, streaming upload с удержанием native lease и normal terminal close. Grant/durable admission в тестах остаётся синтетическим.
