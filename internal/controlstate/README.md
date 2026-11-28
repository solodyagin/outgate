# Durable control state

Implements the initial storage part of [requirements §§3.23 and 5.5.1–5.5.2](../../docs/requirements.md), using the target kinds from [Admin API](../../docs/admin-openapi.yaml).

`Initialize` explicitly provisions schema version 4 in a dedicated control database. `Open` requires the existing database, WAL and owner file, a matching independently provisioned epoch, SQLite WAL/FULL, foreign keys and a successful integrity check. Missing, corrupt or unsupported state is rejected. Published v1/v2/v3 installations require explicit `Upgrade(ctx, config)` while stopped: it takes the owner lock and transactionally preserves epoch, revision, revocations, grants/access, generation checkpoints, operations and pending outbox, adding only missing tables and the registry snapshot sentinel. `Open` never migrates automatically; older readers reject v4 metadata. Repeating Upgrade on valid v4 state is harmless. Legacy layouts never persisted route ownership: migration cannot reconstruct it or declare the registry ready. The epoch is a restore fence supplied by trusted deployment state; detecting an authorized restore and advancing that fence remain deployment responsibilities. Never derive the expected epoch from the database being checked.

The process holds an exclusive nonblocking OS lock on the persistent `.owner` file (Linux flock, Windows LockFileEx). A second process is rejected. Do not delete the lock file while running. Operations check database/WAL/owner file identities, and `Close` waits for checked-out operations before releasing ownership. Unsupported operating systems fail closed. Files are provisioned with owner-only Unix permissions; deployment must also set appropriate Windows directory/file ACLs.

`Revoke` atomically commits a credential revocation, the next control revision, the operation result and an audit outbox event. Supported targets match the existing Admin API contract: service, SPKI SHA-256, certificate serial, grant ID and HMAC key ID, scoped by service. `IsRevoked` also checks the service-wide target and reads the database directly. Database errors deny admission; there is no stale cache or memory fallback. Revision strings retain the entire uint64 range, with overflow rejected.

The caller must authenticate the actor and check current security-admin scope/MFA **before every call**, including retries. The storage layer does not implement RBAC or expose an HTTP endpoint. UUIDv7 operation keys are accepted within the existing 30-day window with 30 seconds of future skew. A retry with identical actor/payload/expected revision returns the original result before checking its old revision; changed input conflicts. A new operation for an already revoked exact target also conflicts. Operation records are currently retained; scheduled 30-day pruning remains unimplemented, and expired keys are rejected even if retained.

The outbox defaults to 100,000 events or 256 MiB of serialized payload, whichever fills first. A full outbox rejects the entire change. `Events` reads at most 200 entries in numeric revision order and limits each persisted payload to 4 KiB before allocating it. A publisher must retry unacknowledged events with their stable operation/event ID, then call `Acknowledge` only after durable external delivery. Acknowledgement does not remove the revocation or operation result. External publishing, disk overhead accounting and 80% capacity alerts remain runtime work.

This remains a storage/security boundary, not a complete production control plane. Routing state, Admin operations lookup, shared revision integration with registry, external outbox publisher, active-flow cancellation, listener callbacks and PostgreSQL remain separate work. No revocation propagation or five-second enforcement guarantee is claimed until the listener/session lifecycle uses this source. No tunnel/Admin wire or normative JSON Schema contracts changed; the internal SQL schema is versioned separately.

Checks cover restart persistence including abrupt process exit without deferred cleanup, cross-process ownership, ownership during concurrent close, concurrent expected-revision conflicts, same-key retries and actor/payload conflicts, service-wide revocation, outbox rollback/full capacity, missing files/epoch/corrupt metadata, and the uint64 boundary. Native Windows execution remains a separate acceptance check.

`Config.Services` supplies a copied, trusted service/registration-prefix allowlist; `RootFrontend` is the only service allowed to receive a root grant. `IssueGrant` validates the complete binding from `deployment-grant.schema.json`, normalizes set order, checks service/SPKI revocations, generates 128-bit grant IDs and 256-bit secrets, and commits only the SHA-256 of decoded secret bytes alongside public binding metadata. The credential is returned only after the first successful commit. Same-key retry, including after expiry/restart or a lost response, returns metadata without a secret; a deployer that lost the first response must revoke and issue a new grant. Secrets and their digests never enter operation results or audit payloads. Grant documents and safe results are bounded at 1 MiB, with paths/mounts constrained before serialization.

`GrantForPeer` requires a previously verified TLS service/instance/SPKI/serial and checks grant lifetime plus service, SPKI, certificate and grant revocations. It is a public-grant-ID metadata check, not independent caller authentication. `VerifyDeploymentGrant` also checks the raw credential digest in constant time and the exact registration service/instance/version/path set/mount map/mode/rewrite/generation. Certificate chain/expiry validation, HMAC key lookup/revocations, route permissions, successful registry publication and acknowledgement still belong to admission/runtime; durable generation and local ownership protection are available through AcquireRegistration; this verification-only method does not acquire ownership or advance a generation; it alone must not acknowledge registration.

`ReplaceAccess` globally replaces policies and internal-only rules in the same durable revision/operation/outbox transaction. The caller must establish current global security-admin scope/MFA **before every invocation**, including retries. New operations additionally require a bound, unused preview; an already committed retry does not require a fresh preview. This does not implement scoped Admin editing. Services must be configured, prefixes canonical and non-root, methods explicit, flags meaningful, sets duplicate-free. Input and returned snapshots are independent copies; canonical set order makes retries insensitive to UI ordering. Storage budgets are 256 policies and 256 internal-only rules, 32 paths/rule, 64 methods/rule, 256 callers/internal rule and a 1 MiB snapshot. Future API/config validation must apply these budgets before dispatch.

`AuthorizeAccess` defaults to deny, uses the original public path decoded once and segment boundaries, distinguishes verified user context from background calls, and applies internal-only caller restrictions. It does not validate signatures/JWT, establish caller identity or prove longest-prefix route ownership. The future listener must combine these checks and revoke/security deadlines. Access reads carry one consistent control revision; stored rules survive restart instead of reverting to YAML. New audit records identify grant issuance/access replacement and include a safe public-payload digest; legacy revocation events remain readable and unmodified.

`AcquireRegistration` verifies the same full grant binding/secret inside a control write transaction. It commits a per-instance global service binding and uint64 generation high-water checkpoint, operation result and audit event before returning a process-local RegistrationLease. A lower generation, a static credential after an atomic generation, a same-generation replacement grant, or reuse of the instance by another service is denied. Current-grant generation checks also apply to signed HTTPS GrantForPeer. Higher issued generations do not advance the fence until registration acquisition. Generation zero remains the static/grant-only profile; operator revocation is required to invalidate an older static grant.

Only one active lease per instance is allowed; different instances are bounded by `Config.MaxRegistrations` (default 1000, maximum 1,000,000). Call Release only after transport/handler cleanup; it is idempotent and a stale release cannot remove a newer owner. Check re-reads current revocations/expiry/generation and confirms that exact lease still owns the instance. Public returned grant metadata cannot alter its private identity. Store.Close returns ErrInstanceInUse while registrations remain, keeping the OS owner lock; stop sessions and retry close. Network ownership is never restored from SQLite after restart. The durable fence survives a process exit/lost ack, and same-pair reconnect remains possible after cleanup. Failed outbox/commit rolls back ownership and generation; an uncertain or successfully committed fence is never rolled back merely because a later registry publication/ack fails. Registry durability/resync must still be supplied by the admission owner.

Migration does not infer generations that a v1/v2 installation never persisted. Before enabling traffic after upgrade, admit the intended current pairs or explicitly revoke obsolete credentials. Registration rate limits, certificate-chain/SPIFFE validation, durable route publication, startup readiness, security-check renewal and revocation fanout belong to the runtime. The QUIC GuardRegistration wrapper supplies the shared TLS identity check and native cleanup attachment, but requires explicit pre-admission and registry-commit callbacks.


`CommitRegistry` stores a validated private format-1 registry snapshot, the next
control revision, a safe operation receipt and audit event in one WAL/FULL
transaction. `nil` expected registry revision is explicit first bootstrap and
accepts only an empty revision-0 snapshot. Initialization/upgrade leave a sentinel;
`LoadRegistry` returns `ErrRegistryUninitialized` until explicit bootstrap. A
missing sentinel is corruption, never permission to bootstrap again. Subsequent
commits require both the expected global control revision and the previous
registry revision, and advance the registry counter by exactly one. Control and
registry counters are distinct: grants/revocations/access also advance control
revision. Persisted registry service revisions remain inside the validated blob.

Service allowlists and frontend identity must match the trusted store config.
`RestoreSnapshot` validates the candidate and previous persisted snapshot; other
normalized permission policies must match on later commits. The caller remains
responsible for authenticating/authorizing the entire mutation (scope/MFA/preview,
including current scope on retries), grant/flow checks, and creating the candidate
from current state. The storage API alone does not authorize route activation or
join registration credential verification into that same transaction.

Operation fingerprints include actor/change, bootstrap/expected registry revision
and the candidate digest. Audit/result records contain only safe digests/revisions,
never the full snapshot or credentials. Same-key retries return the original
receipt even after later commits; a different actor/payload/revision conflicts.
Full/unavailable outbox rolls back the snapshot and both revision/operation state.
An uncertain commit must be resolved by reading/retrying the same operation; a
new operation must not be generated automatically.

`LoadRegistry` reads metadata and blob in one transaction. SQL CASE guards limit
blob allocation to 1 MiB and bound metadata/results before decoding. Reads check
canonical revisions, SHA-256 and the latest registry operation/result binding;
an older row cannot silently replace a later committed snapshot. `Open` checks
the envelope/sentinel, while `LoadRegistry` additionally validates canonical
registry semantics against the supplied trusted config. Keep the latest registry
operation/result when future operation retention is implemented, even if its
outbox event has already been acknowledged.

The load result separates current control revision from the snapshot's commit
revision and registry mutation counter. An independently retained minimum control
revision can reject rollback of the entire database; zero supplies no such proof.
Expected epoch must likewise come from trusted deployment state. Neither an epoch
stored in the same backup nor hashes prove freshness of an entire restored
installation. No automatic backup recovery or rollback clearance is provided.

This completes snapshot storage, not live publication. The caller must serialize
registry mutation/commit/publication, keep existing session handles valid, and
hold readiness closed after uncertain commit until resync. `RestoreSnapshot` is
only cold recovery; swapping it into a live transport owner invalidates handles.
The QUIC registration guard still needs a production commit/publication owner.

## Live registration publication

`OpenRegistrationOwner` loads an explicitly bootstrapped registry using the
trusted configuration, installation epoch and a minimum control revision. It
freezes the configuration and retains the observed watermark. It never creates a
missing snapshot or restores live sessions. Use its stable `Routes()` registry
for transport binding, readiness, routing and cleanup; do not mutate durable
state through that registry's RAM-only Authorized methods.

`RegistrationOwner.Register` takes an `AcquireRegistration` lease and constructs
one candidate. Inside the same SQLite transaction as the snapshot, operation,
control revision and audit outbox, it rechecks the lease's private exact ownership,
current grant service/instance/version/paths/mounts/mode/rewrite/generation,
expiry, generation fence and service/grant/SPKI/certificate revocations. Ownership
is pinned until the transaction finishes, using the same SQL-to-ownership lock
order as admission. Exported mutable lease metadata is never authorization.
Concurrent security changes fail the global control CAS rather than silently
publishing under a different authorization revision. No automatic retry occurs.

Only a confirmed commit publishes the candidate. Existing runtime handles remain
valid; the returned fresh session is unready. Failure/panic in persistence closes
the registry publication barrier. `Resync` performs a verified bounded store read
at or above the retained watermark and reconciles only the known old state or
uncertain candidate. It never acknowledges the failed admission, resurrects its
session, undoes cleanup or restores readiness. A mismatched/corrupt/rolled-back
snapshot leaves the barrier closed; unrelated durable changes need cold recovery.

The runtime can call Register from `GuardRegistration.Commit`, build the ack from
the returned path states/revision, and attach session cleanup to Binding.Release
(including bind/ack errors). Guard supplies TLS identity and a final lease check.
Keep the lease until native cleanup even if publication failed. Registration
rate limiting/startup gate, ack parameters, bounded security renewal (including
registered-but-unready sessions), revocation fanout, Admin mutation publication,
launcher/key loaders and PostgreSQL are separate work. This owner does not assert
SecurityReady or activate pending routes. SQL schema, SDK pin and wire contracts
are unchanged.
