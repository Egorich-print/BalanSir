# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-08-03

### Added

- GitHub Actions CI/CD pipeline
- Documentation for public API
- ADR-000 through ADR-011
- Phase A: IPC authentication (SO_PEERCRED)
- Phase A: MAX_MESSAGE_SIZE validation
- Phase A: DriverError enum (typed errors)
- Phase A: Feature flags for external binaries
- Phase B: Native netlink module (Linux only)
- Phase B: Go runtime memory guardrails (GOMEMLIMIT/GOGC)
- Phase B: Atomic rollback with watchdog
- Phase B: Missing API endpoints (/ready, /live, /version, /build-info, /drivers)
- Phase B: Property testing (proptest)
- Phase C: DriverId as enum (exhaustive matching)
- Phase C: Matcher recursion limit (depth 16)
- Phase C: L3/L7 driver trait split
- Phase C: DomainMatcher/PortMatcher fast lookup
- Phase C: Policy Trie optimization
- Phase D1: Binary size optimization (daemon 704KB, executor 655KB)
- Phase D2: CONTRIBUTING.md, scripts/balansir-cli
- Phase D3: Stress testing suite (1000+ rules, 24h reconciliation sim, IPC burst, EventBus burst)

### Fixed

- Replace `unwrap()` with proper error handling in health.rs
- Replace `unwrap()` with proper error handling in rules.rs
- Remove unused imports
- BoundedEventBus: publish() assigns event ID under mutex (monotonic under concurrency)
- balansir-tests: DriverId constants test updated for enum variant numbering

## [0.3.0] - 2026-08-01

### Added

- Phase 3.5: Xray driver skeleton
- Phase 3.4: WireGuard driver
- Phase 3.3: DriverId newtype, ActionResult enrichment
- Phase 3.2: Full IPC integration tests
- Phase 3.1: Action Model, Executor trait
- Network namespace tests
- DesiredState types

## [0.2.0] - 2026-08-01

### Added

- Phase 2: Policy Engine with matchers
- Decision Trace with SmallVec
- Event ID (monotonic sequence)
- Correlation ID for IPC
- Health Monitor (circuit breaker)
- Time abstraction (Clock trait)

## [0.1.0] - 2026-07-31

### Added

- Initial workspace setup
- balansir-common crate with IPC protocol
- balansir-daemon skeleton
- balansir-executor skeleton
- StateStore (file backend)
- BoundedEventBus
- ResourceAllocator
- NftablesBackend
- DummyDriver
- Hardware profiles (Milk-V Duo S, x86)
- Architecture specification (v7.0)
- ADR-000 through ADR-007
