# Outgate SDK: начало реализации

Модуль `github.com/yourorg/outgate-sdk` пока не опубликован. Прикладной `outgateclient` и transport adapters ещё не реализованы.

`protocol/v1` предоставляет:

- `U64`: JSON decimal string с проверкой канонической записи и overflow.
- QUIC bootstrap `Outgate1` и length-prefixed control frames с ограничениями до выделения буфера.
- Encode/decode WSS binary chunks с 16-byte header и непрозрачным payload.
- `ValidateControlJSON`: ограниченный JSON object, UTF-8, глубина, duplicate keys, surrogate pairs.
- `DecodeRegister`: обязательные/неизвестные/null поля, wire- и семантические ограничения регистрации.
- Negotiation capabilities, нормализацию registration prefixes, однократное декодирование route path и segment matching.

`ReadControl`/`WriteControl` проверяют только framing и общий JSON, а не schema всех сообщений. Из control messages типизирован только `register`. Вызывающий слой отвечает за schema остальных сообщений, направления, session state, лимиты памяти/credit, mTLS/grants/permissions и deadlines. Чтение credentials не является аутентификацией.

`DecodeChunk` возвращает payload, ссылающийся на исходный message buffer. WSS adapter обязан ограничить assembled message до allocation и не переиспользовать buffer до consumption. Wire-лимит chunk не заменяет выданный receiver credit.

Пакет не открывает sockets и не содержит SQL, registry, RBAC или gateway dependencies. Подробные команды проверки — в корневом README.
