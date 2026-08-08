# ADR-011: Runtime Driver Lifecycle

## Status
Accepted

## Context
Hot reload (ADR-010) made desired-state swaps transactional, but it only
handles *rules*. Drivers were untouched: `DesiredDriver { id, action }`
existed, yet `adapters.rs` logged `CreateDriver/RemoveDriver/RestartDriver not
supported`, no driver registry existed, and every `ComponentDriver` was a bare
`start/stop/restart/health_check` pair with no surrounding state machine.

The result: nothing to observe on lifecycle, no idempotence for repeated
reconciles, and — worst — no defined behavior when a driver configuration
changes or an initialization fails mid-flight.

This ADR fixes the lifecycle model *before* M3.3/observability so metrics
subscribe to a stable model, not a temporary mechanism.

## Decision

Introduce a **driver lifecycle state machine** owned by the daemon, independent
of the reconciliation FSM (ADR-010). It models each driver in one of these
states:

```
Absent → Initializing → Active
Active → Replacing → Active          (config changed, new instance okay)
Active → Stopping → Absent          (removed / stop requested)
Active → Degraded / Failed          (runtime failure, distinct from removal)
Failed/Degraded → Recovering → Active (health recovery — no need to change desired)
```

Invariants (fixed now, tested in `driver/lifecycle.rs`):

1. **State machine, not `if` chains.** Every meaningful operation is an explicit
   transition; a failure has a recovery edge, never an undefined state. Illegal
   transitions are programming errors — reject in debug/tests.

2. **Unchanged is a true no-op.** Change detection compares `(DriverId,
   effective-config fingerprint)` served by the daemon factory. If unchanged,
   we must NOT `stop → init → start`.

3. **Change is atomic with the coordinator commit.** The daemon gates the
   coordinator commit (ADR-010) on driver readiness; a driver that fails to
   initialize keeps the previous driver active and policy handles it through its
   health-driven fallback (ADR-008).

4. **Idempotent.** Reconciling the same desired state twice produces no side
   effects; the second call is a pure no-op.

5. **Failure is not removal.** A running driver that cannot apply a new config
   is `Degraded/Failed` — not `Absent`. "Desired present + runtime failed" stays
   in registry; only `Desired absent` causes removal.

6. **Recovery is a first-class state.** A crashing driver goes
   `Active → Degraded/Failed → Recovering → Active` without mutating desired.

7. **Secrets wiped exactly on transitions.** `add → change → remove` must not
   leave the old secret copy in the runtime object; reactive drivers free their
   `SecretString`/`Zeroizing` configs on drop (M2.8) and the manager rotates
   handles so old configs are dropped before new ones become Active.

8. **No observability yet.** M3.2 only emits structured lifecycles as data
   (`DriverLifecycleEvent / DriverStatus/Vec`) so M3.3 can subscribe later.

### Regression scenarios (required before M3.2 closes)
1. `A active → reload to B → B init fails → A stays active → retry B → B init succeeds → B active, A gone`
2. `A active → reload with unchanged fingerprint → same A instance, no stop/init`

## Decision rationale
Drivers live as side-effecting process/kernel handles (child processes, config
files, zeroized secrets). The FSM (rather than a bare
`Vec<(DriverId, Box<dyn ComponentDriver>>)`) makes "drivers are derived state"
explicit and exposes the exact ordering — `build new → stop old → swap` — as
data usable by logs, tests and later metrics.

## Alternatives considered
- Registry-only (`HashMap<DriverId, Box<dyn ComponentDriver>>`) with if-trees in
  `reconcile`: rejected — obscures failure vs removal, no idempotence check.
- Dropping a failed driver from the registry outright: rejected — violates
  invariant 5 (failure ≠ removal).
- Putting the FSM in `balansir-control`: rejected — lifecycle is daemon/process
  business; the control-plane owns policy routing only (ADR-007 layering).

## Related
- ADR-007 (API→ control), ADR-008 (health fallback), ADR-009 (typed errors),
  ADR-010 (transactional reload), M2-8 (secrets zeroize), ROADMAP M3.2.