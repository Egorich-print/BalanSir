# BalanSir Status

> Last updated: 2026-08-02

## Current Phase: Phase 8 (Complete)

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
- [x] BoundedEventBus
- [x] ResourceAllocator
- [x] NftablesBackend
- [x] Drivers:
  - [x] WireGuard
  - [x] AmneziaWG (obfuscation)
  - [x] Xray (VLESS)
  - [x] Hysteria 2 (salamander obfs)
  - [x] B4 (DPI bypass)
  - [x] DNS Forwarder (stub)
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

### Next: Phase 9 (Advanced Features)

- [ ] Hysteria 2 full integration (process management)
- [ ] B4 full integration (iptables/nftables rules)
- [ ] DNS forwarder (full implementation)
- [ ] Batch rule processing (optimize for 8.5k+ rules)
- [ ] Multi-WAN support
- [ ] GeoIP routing

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

**Tests:** 66 passing, 2 ignored (require root)

## Docker

```bash
# Build and run
docker-compose up -d

# Or build manually
docker build -t balansir .
docker run -d -p 8080:8080 --cap-add NET_ADMIN balansir
```

## Web UI

```bash
cd webui && npm install && npm run dev
# http://localhost:5173
```
