# Startup HMAC keyring

`Load(ctx, Config)` resolves the prototype's `secret_env` / `secret_file`
references once, as required by requirements §3.15. Each reference has a key ID
and exactly one source containing canonical padded standard base64. Decoded keys
must contain 32…4096 bytes. Files may have one terminal LF or CRLF; environment
values and embedded whitespace are rejected. Unknown services, duplicate IDs
within a leg/service, missing active recipient IDs and reused secret bytes
across any loaded identities fail startup. Identical key IDs in different
leg/service namespaces remain valid when their secrets differ.

The loader bounds configuration before reading any secret: at most 256 known
services, 16 keys per leg/service and 1024 keys total (at most 4 MiB decoded).
Encoded input is bounded before decoding or reading beyond its limit. Files must
be regular before open and on the opened descriptor, with matching identity and
bounded size; paths with spaces/Unicode work. Deployment-controlled local paths
and their OS ACLs remain the operator's responsibility. These checks are not an
ACL/TOCTOU sandbox or cancellation of arbitrary blocked filesystem IO. No file
descriptors or background goroutines remain after loading. Errors omit paths,
environment names, secret values and decoder diagnostics.

`Config.NotAfter` supplies an explicit finite lifetime for the accepted startup
snapshot; it is required and must be in the future. A launcher must choose this
lifetime along with credential/deployment validity. No default infinite lease or
automatic reread/reload is supplied. The loaded immutable keyring is the local
configuration authority, not a cached remote key server. Changes/removal of file
or env inputs do not replace it while the process runs. Load a new configuration
through a future validated lifecycle or restart the process to change keys.

Wire the loaded source into the existing gateway constructor:

```go
config.State.Keys = ring.Keys
config.KeyHealth = ring.Health
config.RecipientKeyIDs = ring.RecipientKeyIDs()
```

Call `ring.Close()` after gateway shutdown and actual callback cleanup. The owner
must arrange this lifetime; the gateway does not close a borrowed key source.
`Keys` selects only the exact leg/service/key ID and returns a private secret
copy capped by NotAfter. `RecipientKeyIDs` returns a detached active map from the
loaded recipient definitions, using their schema `active_key_id` values.
`Health` asserts only the local ring's open state/lifetime for at most five
seconds, further capped by NotAfter. It does not claim to check files, external
identity providers, durable revocations, certificates or replay state.

StateAdmission continues to check durable service/key revocations and revalidate
the same key after replay commit. Runtime key health supplements the actual
control/replay source, so a healthy static keyring cannot bypass persistent
revocation. Existing signature/authz/exchange deadlines remain in force. Close
immediately makes subsequent lookups/health unavailable and clears owned decoded
buffers; returned copies and process/OS environment strings belong to their
consumers and cannot be wiped by this owner.

Tests cover source/encoding/cardinality boundaries, duplicate/reused keys,
namespace separation, snapshot isolation, lifetime expiry, concurrent reads and
close, sanitized errors, special files and file/env changes after startup.
Gateway integration uses real SQLite to verify that restarting the loader and
control store with old key inputs preserves revocation. Its transport admission
is synthetic; no full signed dispatch or native Windows runtime acceptance is
claimed. Strict YAML/schema validation is implemented in `internal/config`;
bounded certificate loading and shared TLS/HMAC source composition are implemented
in `internal/tlsfiles` and `internal/deployment`. Complete deployment mapping,
JWKS, external source freshness, hot reload and deployment-wide credential
independence remain launcher work.
