# SQLite state and registry mapping

`PlanSQLiteState(document, StateIdentity)` is an IO-free production component plan.
It consumes a validated immutable document and maps the following settings:

| YAML fields | Component result |
| --- | --- |
| `storage.control` | Local SQLite path, WAL/FULL profile, independently supplied control epoch |
| `storage.replay` | Local SQLite path/namespace, WAL/FULL, independently supplied replay epoch, fixed 120s recovery barrier |
| `services.*.allowed_paths`, `rollout` | Registry allowlists/bootstrap rollout and control-store service/path bindings |
| `routing.strategy`, `services.*.instance_routing` | Global strategy inheritance, per-service override, active-passive version orders/preempt/hold-down |
| `frontend_override` | Same designated frontend in registry and control store; initial enabled state in registry |
| `routing.reserved_api_prefixes`, `tunnel.shared_paths` | Registry reserved/shared prefixes; `/api` remains intrinsically reserved by registry |
| `tunnel.max_paths_per_instance`, `max_tunnels`, `max_versions_per_service` | Registry quotas; max_tunnels also bounds control registration owners |
| `security.resource_limits.tunnels_per_service` | Registry per-service tunnel quota |
| `interservice.replay_cache_max_entries`, `replay_max_entries_per_caller` | Replay global/caller capacities |
| `security.rate_limits.signed_per_second`, `signed_burst` | Replay admitted RPS/burst capacity calculation |

Omitted fields receive their schema defaults: round_robin, `/api`, 32 paths,
1000 tunnels, 100 versions, 16 tunnels/service, 200000 replay entries, 20000 per
caller, signed RPS/burst 1000/2000 and 120s recovery barrier. Active-passive hold-down
defaults to 30s; explicit `0s` remains zero. Runtime-owned control outbox defaults
remain with `controlstate.Config` where no YAML setting exists.

The current profile rejects PostgreSQL/Redis, relative/UNC paths, overlapping
lexical database/sidecar/owner names or file-versus-directory layouts, more than
1000000 tunnel owners, non-default active-passive readiness tuning and inactive
active-passive knobs on round-robin services. Default readiness values (5s interval,
2s timeout, healthy/unhealthy thresholds 2/3, 15s status timeout) are accepted;
per-service readiness tuning is not silently discarded. The pinned replay runtime
has a fixed 120s barrier; another configured duration, including a longer one, is
rejected. Durations equivalent to 120s are accepted.

Paths are cleaned using filesystem path rules, never URI rules. Planning uses
host-native absolute path semantics and compares case-insensitively on Windows.
This is a lexical check: filesystem aliases, symlinks/hardlinks, Windows namespace
aliases, actual local storage/durability, ACLs and existing files are not inspected.
Those remain runtime/deployment checks. Planning does not establish distinctness
of actual underlying files or create a filesystem sandbox.

`StateIdentity` requires two nonzero, distinct, independently provisioned epochs
and a nonzero externally supplied minimum control revision. It never generates
identities, derives epochs from filenames or selects a revision from stale YAML.
An external revision floor does not prove freshness against rollback of all trusted
installation evidence together. Restore/migration/recovery require their own
explicitly authorized maintenance procedure.

`Configs()` returns detached inputs for control, registry and replay, including
all nested path lists, active-passive pools and duration pointers. Planning runs
the actual registry validation and bounded initial snapshot encoding, and checks
replay capacity against the pinned runtime's constraints. It does not initialize
stores, publish policy, issue grants, import access rules or touch disk. `Bind(base)`
sets only those state fields in `gateway.Config`; existing state overrides fail.
Security bindings and other runtime inputs remain independent and can be composed
with `SharedSources.Bind`.

Startup still opens already provisioned stores through the existing runtime.
Durable registry recovery remains authoritative: saved rollout replaces the YAML
bootstrap rollout, and missing/stale/invalid state cannot fall back to defaults.
The tests explicitly provision their stores, check newer durable rollout restoration,
revision-floor and epoch rejection, real replay health during its mandatory recovery
barrier, then compose the state/security plans into the real shared constructor.
Admission policy and transport/process budgets remain harness-supplied in that test.

This does not implement a launch plan. Grant/access bootstrap, Admin publication,
full routing timeouts, transport/admission limits, aggregate process budgets,
public/Admin/upstream/audit/JWT configuration, maintenance commands and signals
remain outside this projection. A future launcher must account for all configured
fields and reject an unsupported complete profile before opening traffic.
