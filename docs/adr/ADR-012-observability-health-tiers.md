# ADR-012: Observability — Health Tiers, Metrics, and OTel Deferral

## Status
Accepted (M3.3)

## Context
M3.2 shipped a runtime driver lifecycle FSM (`DriverLifecycleState`) and a
`DriverLifecycleManager` that returns structured `DriverLifecycleEvent`s.
M3.3 (ROADMAP) asks for unified metrics, health tiers
`Healthy → Degraded → Failing → Disabled` surfaced as control-plane events,
and `/metrics` + `/events/stream`.

A naïve approach would push Prometheus and SSE/event-bus calls straight into
`DriverLifecycleManager`. That blurs the mechanism/observability boundary the
FSM was deliberately built to keep (ADR-011) and risks turning the manager
into a god-object ahead of M3.4 (plan engine) and M3.5 (async drivers), which
will add their own concerns.

A second risk is **cardinality**: naively exporting per-reason/error/fingerprint
Prometheus labels would balloon the metrics index for little value, and tying
telemetry to internal error strings freezes those strings into a public contract.

## Decision

### 1. `HealthTier` is an observed-health concept, separate from the lifecycle FSM
Introduce `balansir_common::HealthTier` with four total values:

```
Healthy < Degraded < Failing < Disabled
```

`DriverLifecycleState` stays a *mechanism* concept. The mapping lives in the
**daemon orchestration layer** (`balansir_daemon::driver::health`), not on the
FSM enum and not inside the manager:

| Lifecycle state                          | `HealthTier` |
| ---------------------------------------- | ------------ |
| `Active`                                 | `Healthy`    |
| `Degraded`                               | `Degraded`   |
| `Initializing` / `Replacing` / `Recovering` / `Failed` | `Failing` |
| `Absent` / `Stopping`                    | `Disabled`   |

The FSM already folds `HealthStatus` into lifecycle state via
`DriverLifecycleManager::report_health` (`Active + Degraded → Degraded`,
`Active + Unhealthy → Failed`), so a single-dimension `state → tier`
mapper is sufficient and deterministic.

### 2. The lifecycle manager depends on nothing but its own model
`DriverLifecycleManager::reconcile`/`report_health`/`recover` keep returning
`Vec<DriverLifecycleEvent>` and mutate only registry state. Metrics, the
event bus, and `ControlEvent` emission stay in the daemon orchestration layer:

```
DriverLifecycleManager  ->  Vec<DriverLifecycleEvent>  +  snapshot()
        │
        ▼
   daemon orchestration (main.rs / driver::health)
        ├── TierTracker      (only-on-change dedup)
        ├── SharedMetrics    (Prometheus gauges + counter)
        ├── BoundedEventBus  (Event::ComponentHealthChanged)
        └── ControlEvent::DriverHealthTierChanged { id, tier }
```

### 3. Events are emitted only when the tier changes
`TierTracker` keeps the last emitted tier per driver and emits a
`ComponentHealthChanged` bus event and a `ControlEvent::DriverHealthTierChanged
{ id, tier }` only when the tier differs — including one final `Disabled`
emission when a driver leaves the registry. This keeps `/events/stream` (SSE)
free of duplicate noise and bounds the lifecycle-transitions counter to real
tier changes, not every `report_health` call.

The existing `Event::ComponentHealthChanged { id, status }` envelope is reused;
no new `Event` variant is added. `ControlEvent::DriverHealthTierChanged` is the
*control-plane* contract addition (stable enum, additions-only).

### 4. Metrics: bounded cardinality, no error strings
`SharedMetrics` exposes:

```
balansir_drivers{tier="healthy|degraded|failing|disabled"}   # gauge family, 4 labels
balansir_driver_lifecycle_transitions_total                   # counter
```

No `reason`, no `config fingerprint`, no error-string labels. The label set is
bounded to exactly four tier values. (The counter is registered as
`balansir_driver_lifecycle_transitions` because `prometheus-client` appends
`_total` on encoding.)

### 5. OpenTelemetry export is deferred
> OpenTelemetry export is **deferred**. BalanSir's M3.3 observability contract
> is Prometheus metrics + structured `DriverLifecycleEvent`s/`ControlEvent`s
> consumed via `/metrics` and `/events/stream`. OTel/OTLP will be introduced
> only when an actual collector/backend is selected, layered as an optional
> `tracing` layer, **without changing lifecycle semantics or the event
> contract**.

Adding `opentelemetry` + `opentelemetry-otlp` + `tracing-opentelemetry` now,
without a collector, would bloat the dependency tree and couple telemetry to a
backend that does not exist yet. The current contract is designed so an OTel
layer can subscribe to the same events later with no FSM changes.

## Consequences
- `DriverLifecycleManager` stays metrics/event-agnostic; M3.4/M3.5 can extend it
  without dragging Prometheus or SSE into its unit tests.
- `/events/stream` consumers see one event per real tier change, not per poll.
- Operators get four bounded tier gauges + one transition counter; no
  unbounded-label risk.
- OTel remains a future, additive-only change gated by a real collector need.

## Verification
- `balansir_common`: `HealthTier` roundtrip + `Metrics::set_driver_tiers` family
  encoding tests.
- `balansir_control`: `ControlEvent::DriverHealthTierChanged::name()` test.
- `balansir_daemon::driver::health`: `tier_mapping_is_total_and_deterministic`,
  `tracker_emits_only_on_change` (Healthy → idempotent no-op → Degraded → Disabled
  on removal), `tier_counts_aggregates_snapshot`.
- Workspace gate: `cargo test --workspace` (green), `cargo clippy --workspace
  --all-targets` (0 warnings), `cargo fmt --check` (clean).
