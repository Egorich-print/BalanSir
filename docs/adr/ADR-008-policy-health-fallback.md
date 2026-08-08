# ADR-008: Policy ↔ Health Fallback via HealthView

## Status

Accepted

## Context

`PolicyEngine::evaluate` returned `Action::Allow` for unmatched traffic (fail-open)
and never consulted driver health. `PolicyRule.fallback` was declared but never
read (TECH_DEBT H4): a `Forward { driver }` action always routed into the tunnel
deterministically, even when the target driver was `Unhealthy`. On a real node
this sends traffic into a dead tunnel instead of falling back to another path
or blocking it.

The policy engine lives in `balansir-daemon::policy`; `HealthStatus` already
existed in `balansir-common`. The engine had no dependency on the daemon's
driver registry, which is correct — it must only see a snapshot of health.

## Decision

Introduce `HealthView` in `balansir-common`:

```rust
pub struct HealthView { inner: HashMap<DriverId, HealthStatus> }
```

- `status(driver) -> HealthStatus` (defaults to `Unknown` when untracked).
- `is_routable(driver)` — `true` only for `Healthy` and `Unknown`; `Degraded`
  and `Unhealthy` are not routable. Unknown is deliberately treated as routable
  so a freshly-started daemon with no health data does not start dropping traffic.

`PolicyEngine::evaluate` now takes a health snapshot:

```rust
pub fn evaluate(&self, ctx: &PacketContext, health: &HealthView) -> DecisionTrace
```

Resolution rules, in order:

1. Rules are matched in priority order as before.
2. On a match with `Forward { driver }` where `!health.is_routable(driver)`:
   - use `rule.fallback` when present;
   - otherwise fall back to the engine's default action.
3. The engine default is `Allow` (fail-open, backward compatible) or `Block`
   with the new `PolicyEngine::with_policy(rules, default_deny)` constructor.

The fallback mechanism is the sole consumer of health data; the daemon's actual
driver health probes (per-driver `health_check()`) feed the `HealthView` on the
calling side. The engine itself stays driver-agnostic.

## Consequences

- **Fail-over works**: an unhealthy tunnel no longer causes silent black-hole
  routing; the rule's `fallback` or the engine default takes over.
- **Conservative bail-out**: `Degraded` also fails over, and unknown drivers
  remain routable, so next the health loop converges rather than dropping.
- **API break (internal)**: `evaluate` gained a required `&HealthView`
  parameter. Callers are limited to the daemon's own tests (updated) and
  `tests/stress.rs`; no external consumers.
- **`action` trait/`PolicyRule` shape unchanged**: `fallback: Option<Action>`
  was already present; only the reading path changed.
- Milestone-3 observability will feed the `HealthView` from real per-driver
  health checks (`driver.rs`), keyed by `DriverId`.

## Related

- TECH_DEBT H4, M16; Milestone 2 task 2.6.
- `balansir-daemon/src/policy/mod.rs`, `balansir-common/src/types.rs`.