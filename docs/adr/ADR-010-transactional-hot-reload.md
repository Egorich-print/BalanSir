# ADR-010: Transactional Hot Reload and Runtime Driver Lifecycle Invariants

## Status

Accepted

## Context

Milestone 3 (Runtime/Operations) requires a zero-downtime reconfiguration path:
`/reload` must swap policy/driver configuration **without restarting the daemon**
and must never leave the data path in a half-old/half-new state.

The execution midpoint already is transactional: `Coordinator::reconcile`
(`balansir-control/src/coordinator.rs`) snapshots the pre-execution state,
executes the plan, and on failure runs `rollback_and_fail` restoring that
snapshot. The gap that makes reload unsafe is *upstream of the coordinator*:
the config source silently accepts malformed input.

- `ConfigDesiredProvider` (`balansir-control/src/provider.rs:97-121`) maps a
  `DesiredConfig` to a `DesiredState` with `parse_action(...).unwrap_or(Action::Allow)`
  and `filter_map(parse_driver_id(...).ok())`. An operator typo therefore
  degrades to `Allow`/dropped-driver instead of being rejected — and the new
  (silently wrong) state then commits without error.
- The policy engine (`balansir-daemon/src/policy/rules.rs`) is already strict
  (`PolicyResult`), but nothing wires it into the runtime reload path.

## Decision

Define the reload path as an **atomic transaction** with these invariants:

### Invariant 1 — Strict compile, fail loudly

Parsing a new config file/profiles must be total: any unknown action, unknown
driver, invalid CIDR, or malformed rule is a hard error that aborts the reload.
The current `DesiredConfig → DesiredState` projection becomes fallible
(`TryFrom`, reporting the offending entry). No silent `unwrap_or(Allow)` /
`filter_map().ok()` anywhere on the reload path.

### Invariant 2 — Candidate-then-commit swap

Reload executes in two phases:

```
read raw TOML/config
        │
        ▼
   validate + compile (strict, fallible)   <-- new config rejected here (old stays)
        │
        ▼
   candidate DesiredState (+ compiled PolicyRule set)
        │
        ▼
   reconcile(candidate, ReconcileReason::ConfigReload)
        │
     success  ───────────►  swap candidate into live state, bump generation
        │
     failure  ───────────────►  coordinator rollback restores pre-execution
                               snapshot; on-disk desired_state unchanged
```

The live `DesiredState` is replaced **only after** the candidate reconcil
reconciles successfully. A failed reload leaves the old config active and the
state store holding the old bytes.

### Invariant 3 — Reconciliation is already the commit point

We do not build a second commit mechanism. The coordinator FSM
(`CommitSnapshot → Done`, generation bump) is the single commit boundary. The
reload transaction is responsible for *providing a strict, validated
candidate*; the coordinator owns *atomic application*.

### Invariant 4 — Runtime driver lifecycle states (for M3.2)

The lifecycle manager must model, in addition to routing rules:

- `Added` — driver introduced in desired spec → `start`
- `Changed` — config diff → graceful `stop/start` or `restart`
- `Removed` — driver gone → `stop`, wipe secrets (`zeroize::Zeroizing`),
  uninstall network rules
- `Unchanged` — retained without interruption
- `Failed/unavailable` → health-aware failover (ADR-008) + `unhealthy` state
- `Recovering` — retry/backoff loop, then back to stable on health

Driver lifecycle remains out-of-scope for M3.1 (rules-only reload); M3.2 adds
the `DriverLifecycleManager` on top of these invariants.

### Execution order for M3

1. **M3.1** transactional hot reload (this ADR)
2. **M3.2** driver lifecycle (Invariant 4)
3. **M3.3** observability/metrics over a stable lifecycle
4. **M3.4** plan-engine refactor (deliberately after 3.1–3.3 once the
   plan-vs-orchestration split is observable)
5. **M3.5** async drivers

## Alternatives considered

- Keep `DesiredConfig` lenient and reheal: rejected — silent fallback is
  exactly the half-old/half-new foot-gun this ADR removes.
- Validate in the API layer only: the coord bound must be strict regardless of
  entry point (IPC, TOML, API), so strictness lives in the shared compiler.
- Separate "apply to live" and "persist" phases: rejected — the state store is
  written by the same transaction that commits the live state.

## Related

- ADR-007 (revert-plan rollback) — owns the recovery half of Invariant 3.
- ADR-009 (typed errors) — provides the error taxonomy the strict compiler
  returns; no `String` matching on the reload path.