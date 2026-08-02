# BalanSir Status

> Last updated: 2026-08-03

## Current Phase: Phase A (Critical Fixes) Complete

### Completed

- [x] Architecture specification (v7.0)
- [x] ADR-000 through ADR-010
- [x] Hardware profiles design
- [x] IPC protocol (postcard-based)
- [x] Workspace setup
- [x] balansir-common crate
- [x] balansir-daemon skeleton
- [x] balansir-executor skeleton
- [x] StateStore (file backend)
- [x] BoundedEventBus (Arc<Inner> pattern)
- [x] ResourceAllocator
- [x] NftablesBackend
- [x] Drivers:
  - [x] WireGuard (feature flag)
  - [x] AmneziaWG (feature flag)
  - [x] Xray (VLESS) (feature flag)
  - [x] Hysteria 2 (feature flag)
  - [x] B4 (feature flag)
  - [x] DNS Forwarder (feature flag)
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
- [x] Graceful shutdown (SIGTERM/SIGINT)
- [x] Configuration validation
- [x] Docker image (multi-stage)
- [x] docker-compose.yml
- [x] Phase A: IPC Authentication (SO_PEERCRED)
- [x] Phase A: MAX_MESSAGE_SIZE validation
- [x] Phase A: DriverError enum (typed errors)
- [x] Phase A: Feature flags for external binaries
- [x] Phase A: BoundedEventBus Clone fix (Arc<Inner>)

### Next: Phase B (High Priority)

- [ ] B1: Native netlink (replace `ip` commands)
- [ ] B2: Go runtime memory guardrails (GOMEMLIMIT)
- [ ] B3: Atomic rollback (watchdog)
- [ ] B4: Missing API endpoints (/ready, /live, /version)
- [ ] B5: Property testing (proptest)

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
| IPC Auth | ✅ SO_PEERCRED | ADR-011 |
| Error Typing | ✅ DriverError enum | ADR-012 |

## Drivers

| Driver | Status | Capabilities | Obfuscation |
|--------|--------|--------------|-------------|
| WireGuard | ✅ Complete | TUNNEL | No |
| AmneziaWG | ✅ Complete | TUNNEL | Yes (AWG params) |
| Xray (VLESS) | ✅ Complete | PROXY | Yes (XTLS) |
| Hysteria 2 | ✅ Complete | PROXY | Yes (salamander) |
| B4 | ✅ Complete | PACKET_PROCESSOR | Yes (fragmentation) |
| DNS Forwarder | ✅ Stub | DNS | N/A |

## Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| Daemon RSS | ≤ 12MB | TBD |
| Executor RSS | ≤ 8MB | TBD |
| Policy eval | < 100µs | TBD |
| Firewall apply | < 50ms | TBD |

## GitHub

**Repository:** https://github.com/Egorich-print/BalanSir

**Tests:** 58 passing, 2 ignored (require root)

## Docker

```bash
docker-compose up -d
```

## Web UI

```bash
cd webui && npm install && npm run dev
# http://localhost:5173
```
