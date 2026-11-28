# Shared ingress security mapping

`PlanSharedSecurity(document, notAfter, tunnelNames)` maps the security subset of
an immutable `config.Document` into a detached typed plan. It performs no IO and
requires production mode, QUIC enabled, WSS disabled, explicit future lifetime,
1–64 explicit tunnel DNS/IP identities, 1–256 signed HTTPS authorities and caller
rate/burst compatible with the existing shared runtime (1–1000000). An omitted
QUIC enabled flag retains the schema default; omitted caller rate/burst become
100/200 as specified by the schema. Tunnel identities are supplied by
the deployment owner because bind addresses do not specify client-verified names.
Service DNS/IP identities come from `interservice.allowed_authorities`; authority
ports are validated without DNS resolution. Authorities themselves remain exact.

`plan.Load(ctx)` loads two server pairs and three CA bundles through `tlsfiles`
and then resolves HMAC references through `keyring`:

- `tunnel.tls` and `interservice.tls` must contain the same ordered DER chain.
  Each private key independently matches its leaf. Different reference paths are
  allowed when their loaded identities match; no fallback selects one identity.
- The certificate must match every explicit tunnel name and every configured
  service authority hostname/IP via SAN verification. This does not establish
  that remote clients trust its issuer, or validate the public/browser or Admin
  server certificate. No implicit system roots, network PKI or DNS lookups apply.
- `auth.service_ca_file` and `interservice.tls.client_ca_file` must produce equal
  explicit trust pools, as required by the current shared identity implementation.
  Other otherwise valid TLS profiles return `ErrProfile`, not weaker defaults.
- `admin.tls.client_ca_file` must be separate from the service trust set. Reused
  SPKI (including reissued certificates) and cross-signing trust paths provided
  in either loaded bundle are rejected in both directions. Hidden external PKI
  paths cannot be discovered by this offline check. This does not prove complete
  credential independence across the deployment.
- The accepted source lifetime is the minimum of the supplied HMAC lifetime and
  all loaded server-chain/CA expirations, including Admin CA. Key lookup lifetimes
  and source health respect this minimum. No watches or automatic reload exist.

The existing file limits remain in force: two certificate files ≤1 MiB each,
two private-key files ≤16 KiB each, three CA files ≤1 MiB each, followed by the
bounded HMAC loader. This is a source-size bound, not a process RAM/FD budget or
an adversarial filesystem sandbox. Inputs must be deployment-controlled local
files with operator-managed ACLs. File IO and X.509 operations are synchronous;
context checks do not guarantee interruption of arbitrary blocked filesystem IO.

`SharedSources.Bind(base)` fills only shared security fields in a caller-composed
`gateway.Config`: TLS identity/roots/trust domain, exact HTTPS authorities and
trusted attribute headers, per-caller rates, State.Keys, active recipient IDs and
KeyHealth. Existing overrides of those fields are rejected. DER, private keys,
CA pools, maps and slices are detached for each binding. Other runtime callbacks,
including additional security and user/JWT checks, retain their existing contract.
The shared runtime combines KeyHealth with real control/replay/security readiness;
this source cannot replace durable revocation, replay or exact session admission.

`Health` asserts open/local snapshot validity for at most five seconds. File/env
changes after loading do not change the authoritative startup snapshot. `Close`
immediately denies subsequent callbacks and clears owned HMAC buffers; parsed
private keys and copies returned to runtime consumers are not guaranteed wiped.
Close only after successful runtime shutdown and actual user cleanup, including
cleanup that continues after a shutdown context expires. The runtime borrows these
sources and does not close them. Methods and errors redact source references and
material; context cancellation remains identifiable.

This security projection is not a launcher or a complete typed deployment configuration.
It does not map/serve the public or Admin listeners, storage/initial control state,
full routing/limits, JWT/JWKS, upstream/audit, aggregate budgets, complete credential
independence, signals or maintenance commands. Calling Bind must not be treated as
permission to ignore those YAML sections. Full launch-profile rejection and the
remaining typed mapping are still required before an executable can start traffic.

Tests cover real YAML/file/env loading, SAN errors, identity/pool incompatibility,
CA SPKI reuse and cross-signing, earliest deadlines/expiry, no overrides, detached
bindings, source replacement/removal, concurrent close and redacted errors. A real
SQLite shared-runtime constructor test provisions stores explicitly in its harness,
binds loaded sources, preserves unstarted/warmup refusal and shuts down before
closing borrowed sources. Remaining admission/transport settings in that test are composed by
the harness; state settings are mapped by `PlanSQLiteState` from the same YAML. No full YAML launcher, signed dispatch after the 120s recovery barrier
or native Windows runtime acceptance is claimed.

The [SQLite state/registry component plan](state.md) adds typed mapping for paths,
rollout, active-passive pools, quotas and replay capacity with independently supplied
epochs/revision floor. It composes with the security plan; full launch mapping and
aggregate transport/process budgets remain unfinished.
