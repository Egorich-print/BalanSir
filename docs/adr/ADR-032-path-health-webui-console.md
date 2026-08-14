# ADR-032: Path-health model with hysteresis + single-process WebUI console

Status: accepted (2026-08-14)

## Context
The product question is "is my network OK, why not, what is BalanSir doing".
The WebUI must show one human state per path with raw metrics underneath, and
must not flap on short blips. The console must be a single process with no new
Node/TS backend.

## Decision
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

## Consequences
- No separate web server or backend; token auth protects `/api` only.
- Honest telemetry: `tailscale status --json`, `pgrep xray`, executor health —
  never simulated.
- UI panels: Overview (path health), Policy, QoS, Xray, Tailscale, Events,
  Metrics.
