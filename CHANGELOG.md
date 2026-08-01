# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub Actions CI/CD pipeline
- Documentation for public API
- ADR-000 through ADR-007

### Fixed

- Replace `unwrap()` with proper error handling in health.rs
- Replace `unwrap()` with proper error handling in rules.rs
- Remove unused imports

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
