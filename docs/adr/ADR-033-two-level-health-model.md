# ADR-033: Two-level health model (L1 selection / L2 active-driver lifecycle)

Status: accepted (2026-08-17)

## Context
BalanSir's VPN path has two distinct health concerns that were being conflated:

- **Which profile should serve traffic?** The `VpnPool` answers this via
  per-profile remote probes (`TcpConnectProbe`, L1) feeding the shared
  `PathHealth` model (hysteresis, EMA latency, cooldown). This is a
  *selection* signal.
- **Is the runtime actually alive?** The `XrayManager` runs exactly one active
  driver at a time and supervises it with `driver.health_check()` (L2), which
  verifies the process is alive and the local SOCKS inbound accepts a TCP
  connection.

These are different classes of health and must not be merged into `VpnPool`.
L2 failure means the local process is broken — every profile is equally
unusable — so rotating profiles cannot help; the correct response is a
bounded driver restart. Conflating the two is what produces endless
switch-loops.

### Current gap (motivating defect)
In pool-driven mode, `XrayManager::start_config` sets `self.active = None`
(`xray_manager.rs:370`), so `health_and_failover()` returns early
(`None => return None`, `xray_manager.rs:501`). The pool-driven path
therefore has **no local-liveness supervision today**: if the Xray process
dies while remote endpoints stay reachable, the pool keeps selecting the same
profile, `apply_selected` keeps it running, and no traffic is proxied while
every L1 probe reports success.

## Decision

### Signal definitions (L1 / L2 / L3)
- **L1** — remote TCP reachability of `server:port`. Per-profile.
  *Selection-relevant.* Produces `PathSample` (`reachable`, `latency_ms`).
- **L2** — local active-driver/process health (`kill(pid,0)` + local SOCKS
  inbound accepts, 750ms). Per-active-driver. *Lifecycle-relevant.* Optional,
  driver-specific (non-Xray drivers may not expose it). Produces
  `HealthStatus` (Healthy/Unknown/Degraded/Unhealthy).
- **L3** — real tunneled request (a request carried *through* the tunnel to a
  known-good target). Not implemented deliberately; a future, heavier probe.

### Ownership — one owner per concern
- **`VpnPool`** owns profile health, profile selection, L1. L2 watchdog never
  mutates selection or policy.
- **`XrayManager`** owns the active driver lifecycle, L2, and the bounded
  restart/recovery state machine.
- **Coordinator (`VpnManager`)** owns reconciliation between the selected
  profile and the active driver (today: `apply_selected` →
  `XrayConsumer` → `apply_pool_profile`).

### `Unknown` is a grace/startup window, not a fallback
For a **candidate** (not yet activated) profile, `L2 = Unknown` is normal —
L1-only decides, no L2 required.

For the **active** driver, `L2 = Unknown` is a *time-bounded* grace state
(anchored to `last_switch_ms`, window ~ one health interval). During the
grace window no restart is triggered (the driver is still starting). After the
window expires, `Unknown` is treated as evidence for the recovery state
machine — a driver that never becomes `Healthy` (nor `Degraded`) is stuck and
must be restarted. `Unknown` must never mean "keep counting as fine".

### Bounded restart/recovery state machine (not a "circuit breaker")
Terminology: this is a **lifecycle recovery guard**, deliberately *not* part
of the pool health model and *not* named a circuit breaker. `PathHealth` has
hysteresis+cooldown, `VpnPool` has dwell/rotation gates, `XrayManager` gets
its own bounded recovery — each is scoped to its owner and none leaks.

State machine (L2, active driver only):

| L2 result            | Action                                            |
| -------------------- | ------------------------------------------------- |
| `Healthy`            | no-op; converge                                   |
| `Unknown`            | grace/startup window only; no restart yet         |
| `Degraded`           | watchdog evidence → bounded restart (backoff)     |
| `Unhealthy`/Failed   | bounded restart (backoff); after exhaustion → `apply_selected(None)` |

Recovery rules:
- Restarts are bounded (max N within a window) with backoff — a real
  "recovery guard", stopping the endless switch-loop.
- L2 result is fed back to the pool **only via reconciliation** (the
  coordinator calls `apply_selected(None)` on exhaustion), never as a direct
  mutation of profile ranking.
- `apply_selected(None)` → `VpnPool` clears `active` (see the stale-active
  fix, `audit/k3-recovered` → `debcaa2` semantics) → XrayManager
  `stop_driver()` → traffic direct. This is the documented honesty rule.

### Composition for `PathSample` (active profile only)
- `latency_ms` ← L1 (unchanged).
- `reachable` ← `L1.reachable && (L2 == Healthy | grace)`.
- `degraded_evidence` ← `L2 == Degraded` (the existing qualitative field,
  `balansir-health` lib.rs).
- L2 `Healthy`/grace → no change. L2 only ever downgrades, never upgrades.

L2 must never influence candidate ranking (`select_for`). It is
per-active-driver and lifecycle-relevant; L1 is per-profile and
selection-relevant.

## State / influence table

| State                  | Who evaluates          | Affects selection? | Action                              |
| ---------------------- | ---------------------- | ----------------- | ----------------------------------- |
| L1 fail                | VpnPool                | Yes               | degrade/fail profile (weight → 0)   |
| L2 fail                | XrayManager            | No                | bounded restart (backoff)           |
| L2 restart exhausted   | XrayManager/coordinator| Indirect          | `active = None` (traffic direct)    |
| L3 fail                | —                      | —                 | Future                              |

## Consequences
- Pool-driven mode gains real local-liveness supervision (closes the gap
  above) without mixing L2 into `PathHealth` ranking.
- One owner per concern: no two components write the same state.
- Clear vocabulary: L1/L2/L3, grace window, recovery guard — no new
  "circuit breaker" concept scattered across subsystems.
- `Unknown` is explicitly a startup/grace state with a bound, so a stuck
  driver cannot silently "count as fine" forever.
- Implementation is a follow-up (new branch off `audit/vpn-health-probe`
  work, now merged to `main` at `caa96f8`).