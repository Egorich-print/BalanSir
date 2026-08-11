# ADR-020: Desired/kernel ownership model (P4.1)

## Status
Accepted (P4.1)

## Context

The gate and the A2 work established the *mechanism* for orphan detection
(executor inventory + `sync_actual_from_executor`), but the **ownership
model** was incomplete: the daemon seeded `ActualState` from the inventory
once at startup and reconciled once. There was no ongoing converge loop, and
no periodic re-seed — so:

- an **external kernel edit** (another tool adds/removes an nft rule) was
  invisible to a `Desired − Actual` diff on stale accounting;
- an **executor restart** that re-imports its nft chain could diverge the
  kernel from what the daemon believed, undetected until daemon restart.

The roadmap's P4.1 ("Desired/Actual/kernel ownership") names this the most
important production-readiness problem. The constraint that must hold: the
**executor never becomes the authority**. It is a *mechanism of observation
and execution*; it reports what *is* in the kernel, and the daemon decides
what *should* be. `DesiredState` is the sole authority.

## Decision

Formalize ownership as: **DesiredState owns; the kernel is owned; the daemon
converges; the executor observes and executes.** Concretely:

1. **Ownership authority** — `DesiredState` is the only source of "what should
   exist". No executor-side desired state, no second planner (unchanged from
   ADR-015/016/018).
2. **Observation** — the executor reports its kernel inventory
   (`actual_rule_ids`, A2). The inventory is non-authoritative: it seeds
   `ActualState` so the planner can see orphans, but it does not decide what
   should be present.
3. **Converge loop** — the daemon runs a periodic ownership loop
   (`Reconciler::run_loop`) that reconciles `Desired − Actual` on a cadence
   (`check_interval_secs`), and every `resync_every_n_cycles` cycles re-seeds
   `ActualState` from the executor inventory *before* diffing.
4. **Explicit resync** — `sync_actual_from_executor()` remains callable on
   demand (startup, reconnect), and is the same path the loop uses.

The loop body is `Reconciler::step(cycle)`: optional resync, then an atomic
reconcile. `run_loop` is a thin timer wrapper over `step`, so the ownership
logic is testable without wall-clock waits.

The default is `resync_every_n_cycles = 3` (a resync each 3 cycles). The
executor inventory call is cheap (one `nft list`); the default keeps a
bounded cost while making external edits visible on a minute-ish timescale.

## Consequences

- **External kernel edits converge back to DesiredState.** A rule injected
  outside the daemon is seen on the next resync cycle and removed if not
  desired (verified by `ownership_loop_converges_external_kernel_edit`).
- **Executor restarts are discovered** by the periodic resync even when the
  daemon stayed up — closing the A2 "reconnect-time seeding is a future
  refinement" note.
- The executor stays non-authoritative: the loop only reads its inventory and
  executes the planner's ops; authority remains `DesiredState`.
- `ReconcilerConfig` gains `resync_every_n_cycles`; `0` disables periodic
  resync (explicit calls only), preserving prior behavior for callers that
  do not want the loop (e.g. the stress test sets `0`).
- The daemon binary now spawns `run_loop` as a background task after the
  startup reconcile, so the control-plane process continuously converges
  instead of settling after one cycle.

## Verification

- `ownership_loop_converges_external_kernel_edit`: desired rule installed;
  external id injected into the fake kernel; one `step` (resync + reconcile)
  discovers it and removes it; final kernel == desired, `ActualState` matches.
- Existing A2 round-trip (`sync_actual_from_executor_imports_kernel_inventory`)
  still passes.
- Workspace 18 suites, clippy 0, fmt clean; x86_64 + aarch64 Linux check pass.

## Relation to other gates

- Builds on **A2/ADR-016** (inventory) and completes its deferred
  reconnect-time seeding via the periodic loop.
- Keeps the executor non-authoritative (A1/A2/A3 + P1 constraint).
- Feeds the roadmap's P4.2+ (rule identity) and P5.4 (warm-up) later: the
  ownership loop is the heartbeat over which selection/warm-up will compose.
