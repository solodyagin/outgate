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
The publication owner still needs a fail-closed barrier between uncertain commit
and successful resync, plus admission authorization in the commit transaction.
It must also keep existing transport session handles valid during publication;
`RestoreSnapshot` is a cold recovery operation, not a live registry replacement.
