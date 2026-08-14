# ADR-032: Path-health model with hysteresis + single-process WebUI console

Status: superseded (2026-08-14) — replaced by the unified
`balansir-common::path_health::PathHealth` model; see the module docs and the
path-health section of `ARCHITECTURE_AUDIT.md` for the live design.

## Context
The product question is "is my network OK, why not, what is BalanSir doing".
The WebUI must show one human state per path with raw metrics underneath, and
must not flap on short blips. The console must be a single process with no new
Node/TS backend.

## Decision (original, 2026-08-14)
- `PathHealthTracker` (daemon/health.rs): per-path state machine
  (Unknown/Healthy/Degrading/Degraded/Recovering) requiring N consecutive bad
  samples to degrade and M good to recover (hysteresis). The daemon probes
  `direct` (ICMP), `b4` (executor health), `tailscale` (backend Running) every
  15s and feeds samples; WebUI reads reports via `GET /api/health/paths`.
- WebUI backend: the daemon process itself serves the Svelte static build
  (`BALANSIR_WEBUI_DIR`) at `/` plus the REST/SSE API at `/api` — one process,
  auth middleware scoped to `/api` only.
- Per-subsystem status endpoints: `/api/qos/status`, `/api/tailscale/*`,
  `/api/xray/status`, `/api/health/paths`.

## What actually landed
The daemon-local `PathHealthTracker` was never wired into any decision path
and was removed as dead code. Path health today is the **shared
`PathHealth` model in `balansir-common`** — one state vocabulary
(Unknown/Healthy/Degraded/Failing), EMA latency smoothing, hysteresis via
`enter_degraded`/`exit_degraded`, and an anti-flapping cooldown — used by the
Xray manager (per-endpoint health driving failover) and the B4 engine
(per-flow classification projection). Health observations flow through the
unified subsystem snapshot (`/subsystems`), not a separate `/api/health/paths`
endpoint; the WebUI renders the same `PathHealthView` that the managers use,
so the UI can never disagree with the failover decision.

## Consequences
- No separate web server or backend; token auth protects `/api` only.
- Honest telemetry: `tailscale status --json`, `pgrep xray`, executor health —
  never simulated.
- UI panels: Overview (path health), Policy, QoS, Xray, Tailscale, Events,
  Metrics.
