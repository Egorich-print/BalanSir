# BalanSir Status

> Last updated: 2026-08-03

## Current Phase: Phase D (Technical Debt) — D3 Stress Testing Complete

### Completed

- [x] Architecture specification (v7.0)
- [x] ADR-000 through ADR-011
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
- [x] Phase B: Native netlink (Linux only)
- [x] Phase B: Go runtime memory guardrails (GOMEMLIMIT/GOGC)
- [x] Phase B: Atomic rollback + watchdog
- [x] Phase B: Missing API endpoints (/ready, /live, /version, /build-info, /drivers)
- [x] Phase B: Property testing (proptest)
- [x] Phase C: DriverId as enum (exhaustive matching)
- [x] Phase C: Matcher recursion limit (depth 16)
- [x] Phase C: L3/L7 driver trait split
- [x] Phase C: DomainMatcher/PortMatcher fast lookup
- [x] Phase C: Policy Trie optimization
- [x] Phase D1: Binary size optimization (daemon 704KB, executor 655KB)
- [x] Phase D2: CONTRIBUTING.md + scripts/balansir-cli
- [x] Phase D3: Stress testing
  - [x] Policy engine: 1000+ rules, timing measured
  - [x] Reconciliation: 24h simulation (2880 cycles, rule churn)
  - [x] EventBus: 100k burst, drop-oldest semantics, concurrent publishers
  - [x] IPC: 10k message burst over Unix socket
  - [x] Fixed EventBus publish() race (ID assignment moved under mutex)

### Next

- [ ] v0.1.0 release (tag, CHANGELOG)
- [ ] Verify `make install` on macOS
- [ ] Push to Forgejo backup

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
| Daemon RSS | ≤ 12MB | TBD (target device) |
| Executor RSS | ≤ 8MB | TBD (target device) |
| Policy eval | < 100µs | ~10.9µs (debug, 1024 rules) |
| Firewall apply | < 50ms | TBD (target device) |

## GitHub

**Repository:** https://github.com/Egorich-print/BalanSir

**Tests:** 70 passing, 2 ignored (require root) + 5 proptest suites

## Docker

```bash
docker-compose up -d
```

## Web UI

```bash
cd webui && npm install && npm run dev
# http://localhost:5173
```
