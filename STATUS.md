# BalanSir Status

> Last updated: 2026-07-31

## Current Phase: Phase 1 (Core Foundation)

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
- [x] WireGuard driver skeleton
- [x] Decision Trace
- [x] Event ID (monotonic)
- [x] Correlation ID for IPC
- [x] Time abstraction (Clock trait)
- [x] Policy Engine (matchers, actions)
- [x] Health Monitor (circuit breaker)

### In Progress

- [ ] Full WireGuard driver
- [ ] Xray driver
- [ ] Integration tests (netns)

### Blocked

- None

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

## Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| Daemon RSS | ≤ 12MB | TBD |
| Executor RSS | ≤ 8MB | TBD |
| Policy eval | < 100µs | TBD |
| Firewall apply | < 50ms | TBD |

## Next Milestone

**Walking Skeleton**: daemon + executor + IPC + dummy driver + basic policy
