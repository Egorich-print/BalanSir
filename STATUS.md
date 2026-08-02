# BalanSir Status

> Last updated: 2026-08-02

## Current Phase: Phase 6 (Complete)

### Completed

- [x] Architecture specification (v7.0)
- [x] ADR-000 through ADR-018
- [x] Hardware profiles design
- [x] IPC protocol (postcard-based)
- [x] Workspace setup
- [x] balansir-common crate
- [x] balansir-daemon skeleton
- [x] balansir-executor skeleton
- [x] StateStore (file backend)
- [x] BoundedEventBus
- [x] ResourceAllocator
- [x] NftablesBackend
- [x] DummyDriver
- [x] WireGuard driver
- [x] Xray driver
- [x] AmneziaWG driver
- [x] Decision Trace
- [x] Event ID (monotonic)
- [x] Correlation ID for IPC
- [x] Time abstraction (Clock trait)
- [x] Policy Engine (matchers, actions)
- [x] Health Monitor (circuit breaker)
- [x] Action Model (Route, Mark, Forward, Block, Reject)
- [x] Executor trait + DummyExecutor
- [x] Full IPC integration tests
- [x] DriverId newtype
- [x] ActionResult enrichment
- [x] Network namespace tests
- [x] Reconciliation loop
- [x] Crash recovery (bootstrap)
- [x] GitHub Actions CI/CD
- [x] Polished code (clippy, unwrap fixes, docs)
- [x] Prometheus metrics (/metrics endpoint)
- [x] REST API (axum)
- [x] SSE Event Stream (/events/stream)
- [x] Web UI (Svelte dashboard)

### Next: Phase 7 (High Availability)

- [ ] State export/import
- [ ] Multi-node sync (optional)
- [ ] Hysteria 2 driver
- [ ] B4 driver
- [ ] DNS forwarder

## Architecture Decisions

| Decision | Status | ADR |
|----------|--------|-----|
| StateStore backend | ✅ File (default), Redb (optional) | ADR-001 |
| Driver model | ✅ Enum in prod, dyn in SDK | ADR-002 |
| Runtime | ✅ current_thread (embedded), multi_thread (desktop) | ADR-003 |
| IPC | ✅ postcard + length framing | ADR-004 |
| Privilege separation | ✅ daemon + executor | ADR-005 |
| Health | ✅ Circuit breaker | ADR-006 |
| Updates | ✅ A/B slots | ADR-007 |
| Reconciliation | ✅ Desired state + drift detection | ADR-008 |
| Observability | ✅ Prometheus metrics | ADR-009 |
| API | ✅ REST + SSE | ADR-010 |

## Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| Daemon RSS | ≤ 12MB | TBD |
| Executor RSS | ≤ 8MB | TBD |
| Policy eval | < 100µs | TBD |
| Firewall apply | < 50ms | TBD |

## GitHub

**Repository:** https://github.com/Egorich-print/BalanSir

**Tests:** 52 passing, 2 ignored (require root)

## Drivers

| Driver | Status | Obfuscation |
|--------|--------|-------------|
| WireGuard | ✅ Complete | No |
| AmneziaWG | ✅ Complete | Yes (Jc, Jmin, Jmax, S1, S2, H1, H2, H3) |
| Xray (VLESS) | ✅ Complete | Yes (XTLS) |
| Hysteria 2 | ⏳ Pending | Yes (built-in) |
| B4 | ⏳ Pending | Yes (DPI bypass) |

## Web UI

```
http://localhost:5173
```

- Health status
- Real-time events (SSE)
- Desired state
- Metrics
- Manual reconcile
