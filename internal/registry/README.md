# Registry recovery boundary

The registry models route ownership, rollout, discovery and live selection.
Authentication, durable SQL transactions, audit publication and runtime recovery
readiness belong to the admission/control owner.

`MarshalSnapshot` captures a consistent, detached internal JSON document.
`RestoreSnapshot` builds a new isolated registry from that document. Format 1
preserves global/service revisions, pending/active/retired ownership (including
shared owners), rollout/previous-stable, root enablement, development release
markers, version tombstones, discovery mounts and historical version metadata.
It never restores live sessions, readiness, transport bindings, primary session
handles or round-robin counters. Retained active/retired routes return `503`
until a fresh authorized session becomes ready; pending routes do not enter
longest-prefix routing. Root/rollout state is not reset from bootstrap YAML.

Recovery requires the same normalized service allowlists, active-passive pools,
shared/reserved paths, frontend identity and development/production profile.
Changing these permissions requires an explicit future control transaction or
migration. Runtime quotas may differ, but a live-version quota smaller than the
recovered state fails closed. Versions' paths are historical unions and can
include released routes; mounts must still reference current ownership.

This private format is independent of tunnel wire, Admin API and SQL schema.
Only the exact canonical encoding produced by `MarshalSnapshot` is accepted:
unknown/duplicate/missing fields, trailing data, invalid revisions, noncanonical
paths and inconsistent ownership/mounts are rejected. Documents are limited to
1 MiB. The control-state store checks SQL blob length before allocation.
Exceeding the encoding budget returns `ErrSnapshot`; it does not discard history.

These functions do **not** make the registry durable. They cannot authenticate
a document, establish installation epoch, detect rollback to an older snapshot,
or join a route mutation to a grant/revision/operation/outbox transaction.
Do not acknowledge `GuardRegistration.Commit` merely after taking a snapshot.
The [control-state store](../controlstate/README.md) supplies atomic snapshot/
revision/operation/outbox commits, bounded reads and epoch/watermark checks.

`CommitRegistrationAuthorized` builds one private candidate while serializing
registration, persistence and publication under the live registry lock. The
persistence callback must use a bounded storage context, atomically commit the
snapshot/revision/operation/outbox and recheck admission permissions. It must not
reenter the registry. Existing session pointers, transport bindings, readiness,
primary handles and selection counters survive a successful publication; the
new session starts unready. Validation/encoding errors never invoke persistence.

An error or panic after entering persistence blocks lookup (including upstream
fallback), dispatch, discovery, binding, readiness promotion and further durable
mutations. Drain, readiness exclusion and disconnect remain available. The
barrier does not cancel requests already dispatched; revocation cancellation
remains a runtime responsibility. `ReconcileRegistrationAuthorized` accepts only
a verified durable snapshot exactly matching the pre-commit state or the failed
candidate. An owner must first verify epoch, semantics and a retained control
watermark through `LoadRegistry`; raw bytes are not freshness evidence. An
unrelated durable snapshot requires cold recovery. Resync preserves surviving
handles and cleanup performed during the barrier, drops the failed admission's
session and clears readiness until status/security are re-established.

`controlstate.RegistrationOwner` implements this persistence/recovery owner for
registration. RAM-only mutation methods remain models for authorized callers;
production must not bypass the owner. Administrative activation/rollout/release,
flow/grant checks, MFA/preview and durable manual-primary intent still require
separate publication transactions. `RestoreSnapshot` remains cold recovery,
never a live registry replacement.
