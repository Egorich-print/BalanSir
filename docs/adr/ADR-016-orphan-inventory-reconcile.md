# ADR-016: Orphan Reconciliation via Executor Inventory (A2)

## Status
Accepted (Architecture Gate A2)

## Context

The daemon reconciles by diffing `DesiredState` against its in-memory
`ActualState`, which it mutates from the `ActionResult`s it receives. That
accounting has an ack-gap: if the executor applies an `AddRule` but the
`ResponseOk` is lost, or the executor restarts and re-imports its nft
chain from disk while the daemon's `ActualState` was cleared, the daemon
no longer knows a rule is present. It never emits `RemovePolicy(id)` for a
rule it believes is absent — so the orphaned kernel rule persists forever.

ADR-015 established a deterministic identity for a rule (semantic
fingerprint) but explicitly deferred this decision: "does not solve the
ack-gap orphan by itself (that is A2's reconcile decision)."

The reconcile decision must not give the executor authority: the daemon
is the sole control-plane authority. The executor must not decide what
*should* be present — it can only report what *is*.

## Decision

Introduce a **non-authoritative kernel inventory**: the executor reports
the ids of the rules currently present in its mechanism, and the daemon
seeds its `ActualState` from that report before reconciling.

- Executor side: `Executor::actual_rule_ids()` — implemented by
  `NftablesExecutor::list_rule_ids()`, which parses `balansir:<id>`
  comments out of `nft list chain`. The default trait impl returns empty
  for mechanisms with no kernel state.
- IPC: new allow-listed op `GetActualRules`. The dispatch handler encodes
  the `Vec<u32>` inventory with postcard.
- Daemon side: `ExecutorClient::actual_rule_ids()` decodes the inventory;
  `Reconciler::sync_actual_from_executor()` replaces `ActualState` with
  `ActualRule { id, action: Allow, rule_id: None }` entries from it; the
  daemon then runs a normal reconcile.
- Startup wiring: `main.rs` calls `sync_actual_from_executor()` before the
  initial reconcile. A failed inventory read only warns — reconcile still
  proceeds (empty/unchanged ActualState is the pre-A2 behavior).

The inventory carries ids only, not actions. Seeded rules use a neutral
placeholder action (`Allow`). This is safe because:

- Orphan removal is id-based: any rule present in the kernel but absent
  from desired is emitted as `RemovePolicy(id)` regardless of the stored
  action.
- A rule present in both sides but differing in action is re-applied by
  the planner; ADR-015 makes that `AlreadyApplied` no-op idempotent.

## Consequences

- Orphans from ack-gaps or executor restarts are reconciled away: startup
  seeds truth from the kernel instead of from possibly-stale accounting.
- The executor remains non-authoritative: it reports what *is*, never what
  *should* be. The daemon still runs the single planner (M3.4.2).
- The inventory is bounded to rule ids — no second state contract, no
  planner split. Action/flow comparison stays in the daemon's diff where
  the planner owns it.
- An executor that cannot be reached at startup still bootstraps (warn,
  not abort); a later successful reconcile would still not see orphans
  until the next process start — reconnect-time seeding is a future
  refinement, not a regression.

## Verification

- `sync_actual_from_executor_imports_kernel_inventory` (daemon): a fake
  adapter inventory `[7, 42]` seeds `ActualState.active_rules` with those
  ids.
- `get_actual_rules_returns_inventory` (executor): `GetActualRules`
  dispatch is allow-listed and returns a decodable empty inventory.
- Workspace 18 suites green, clippy 0, fmt clean.

## Relation to other gates

- Builds on **A1/ADR-015**: the idempotent re-apply path makes the
  placeholder-action seed safe.
- Supplies the reconcile input for later **A3** flow-criteria rules: the
  inventory shape (ids) is unchanged; comparison of richer criteria stays
  in the daemon planner.
