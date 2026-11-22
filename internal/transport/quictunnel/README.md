# Gateway QUIC transport boundary

`Accept` принимает существующий quic-go connection и обязательный `quiccontrol.Authorize`. Успешный bootstrap/ack подключает single-session reverse HTTP/3 из опубликованной закреплённой SDK revision. Gateway не использует local replace, соседний SDK checkout или go.work для сборки и tests.

`Session` предоставляет `http.RoundTripper`, `Send`/`Receive` для session control и `Done`/`Err`/`Close`. Request ID sanitization, bounded inflight, streaming/SSE, independent EOF и cancel реализует SDK `transport/quichttp`; автоматические dial/retry/redirect отсутствуют. CONNECT/virtual HTTP/1.1/Hijacker пока не подключены.

Authorizer обязан проверить transport identity, grant, permissions, expiry/revocation, конфликты и durable commit до ack. `Accept` сам не публикует маршруты и не устанавливает readiness. Вызывающий слой должен обработать status/commands через sessionstate, связать accepted handle с registry, проверять готовность/security перед каждым назначением и исключить session по Done/неудаче ack. Эти integration layers и durable backend ещё предстоит реализовать. SQL/RAM-подмена production допуска отсутствует.

Tests выполняют реальный mTLS bootstrap из опубликованного SDK, ordinary HTTP с точным Host/raw query и удалением внешнего transport ID, status/drain одновременно с HTTP и cleanup при закрытии carrier. Authorization callback синтетический; эти tests не означают production acceptance или работающий gateway executable.
