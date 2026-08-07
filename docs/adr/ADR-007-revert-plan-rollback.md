# ADR-007: Revert-Plan Rollback via Executor

## Status

Accepted

## Context

`DaemonRollback` (`reconciliation/adapters.rs`) previously restored only the
in-memory `ActualState` on a failed reconcile (H3). It never touched the
kernel/mechanism layer, so partially-applied rules persisted in the executor
even after a reported rollback. The coordinator's `Rollback` port received only
a `Snapshot`, giving no direct handle to the executor's undo machinery.

## Decision

`DaemonRollback` now performs a **diff-driven revert plan**:

1. Compute rules the failed execution added: present in the live `ActualState`
   but absent from the pre-execution snapshot.
2. For each such rule, call `ExecutorAdapter::remove_rule(id)` — the
   mechanism-level undo. Failures are logged but do not abort the rollback.
3. Restore the in-memory `ActualState` from the snapshot, as before.

`ExecutorAdapter` gained an explicit `remove_rule(rule_id)` method (previously
implicit). Undo is pushed to the same interface that applied the rule, keeping a
single mechanism boundary and preserving the hexagonal policy/mechanism split.

No new abstraction was introduced: the existing `Rollback` port + `ExecutorAdapter`
are reused. Driver-creation/drop semantics remain out of scope—they are handled
thread-safe elsewhere (see ADR-010 planned in Milestone 3).

## Consequences

- **Correctness**: rollback now reverts mechanism-side changes, not just the
  in-memory snapshot, closing the H3 gap.
- **API surface**: `ExecutorAdapter` gains one method; `DummyExecutorAdapter`,
  `CountingExecutor`/`OkExecutor` (stress tests) implement it. No external crate uses it.
- **Scope limit**: does not yet drive real IPC `undo` for netlink/nft; those
  mechanisms land with the executor IPC wiring (roadmap M3.x). This ADR's
  revert-plan design is mechanism-agnostic and applies to any
  `ExecutorAdapter::remove_rule` backend.
- **Safety**: removal failures are non-fatal (logged), exactly like the previous
  in-memory-only path, so a partial revert still converges on the memory view.

## Related

- ADR-002 (driver model, policy/mechanism).
- `TECH_DEBT.md` H3; Milestone 2, task 2.4.