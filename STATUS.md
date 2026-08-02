# BalanSir Status

> Last updated: 2026-08-01

## Current Phase: Phase 4 (Complete)

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

### Next: Phase 5 (Observability + API + UI)

- [ ] Observability (metrics + tracing)
- [ ] REST API
- [ ] Web UI
- [ ] Package Manager

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

## Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| Daemon RSS | ≤ 12MB | TBD |
| Executor RSS | ≤ 8MB | TBD |
| Policy eval | < 100µs | TBD |
| Firewall apply | < 50ms | TBD |

## GitHub

**Repository:** https://github.com/Egorich-print/BalanSir

**Tests:** 43 passing, 2 ignored (require root)

## Next Milestone

**Phase 5:** Observability (Prometheus metrics) → REST API → Web UI
