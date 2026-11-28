# Startup configuration validation

`Parse(ctx, source)` accepts a gateway YAML document without resolving references,
opening listeners, contacting stores or fetching schemas. It embeds the normative
`docs/config.schema.json` directly through the `docs` Go package; there is no
second schema snapshot or runtime schema-file dependency.

The parser accepts one UTF-8 mapping, up to 1 MiB of source, with conversion limits
of 64 nested levels, 32768 nodes (including mapping keys) and 16 KiB per scalar.
The YAML library composes an input-size-bounded node tree before conversion checks;
these limits are not a measured process RSS budget. Anchors, aliases, merge keys,
non-string keys, duplicate keys and explicit tags other than `!!str` are rejected.
Quoted and block scalars remain strings. Plain lowercase `true`/`false`, `null`
(or empty values) and canonical decimal integers resolve to JSON primitives;
other scalars, including dates, `on`, `yes`, hex and floating-point spellings,
remain strings, matching the offline fixture validator's implicit scalar profile.

Draft 2020-12 validation enforces required/unknown fields, mode-specific requirements,
ranges, selectors and conditional rules. Production is the default mode. Schema
patterns use ECMAScript regex with a 50 ms per-match timeout; a regex error fails the
whole document even inside a conditional or negated branch. Schema validation is
serialized; it checks cancellation after acquiring the lock and on return. YAML
composition and individual schema matches are synchronous, not interruptible tasks.
No parser or schema diagnostics, field names, references or source values enter
returned errors. Context cancellation remains identifiable.

Additional checks cover Go duration representation, nanosecond positivity, UTF-8
version byte limits, listen ports, CIDRs, normalized service prefix uniqueness/root
permissions, rollout/active-passive orders and readiness timing, transport timing,
HMAC service/key/active-ID references and cardinality, policy keyrings, development
bearer references, production replay capacity/recovery/startup grace, buffer budget
ordering and certificate/grant lifetime ceilings. These follow the existing offline
configuration checks and the relevant runtime constraints. Defaults used by checks
are explicit; defaults are not generally inserted into the returned document.

`Document` owns an immutable snapshot; `Values()` explicitly returns a detached,
sensitive copy. Its string formatting is redacted. `KeyringConfig(notAfter)` maps
service IDs, caller/recipient key references and active IDs into `keyring.Config`
with an explicit finite lifetime supplied by the owner. `keyring.Load` independently
validates and resolves these references, including secret independence.

This is a validated input boundary, not deployment acceptance. Full typed mapping,
complete listener/TLS mapping, deployment-wide hostname/trust/credential-independence
checks, JWKS, aggregate process reservations, store provisioning and runtime ownership/deadline enforcement
remain to be connected. `config validate`/`config explain`, maintenance subcommands,
executable/signal wiring and hot reload are not implemented by this package. The
parser must not be used to start a partially mapped deployment or to silently
ignore configuration fields unsupported by a launcher.

The shared QUIC/signed-HTTPS security subset is now mapped separately by
[`internal/deployment`](../deployment/README.md), including bounded TLS/HMAC loading,
SAN checks, Admin/service CA separation and source deadlines. This does not complete
the remaining deployment mapping or authorize a partial launch.
