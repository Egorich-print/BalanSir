# BalanSir Full Software Audit

**Date**: 2026-08-17
**HEAD**: `78c132c`

## Architecture Overview

```
balansir-common     — shared types, IPC, path health, gateway config, path pool
balansir-control    — reconciliation engine, planner, coordinator
balansir-daemon     — unprivileged daemon: drivers, DNS, B4, VPN, policy, subsystems
balansir-executor   — privileged: nftables, QoS, routes, gateway backend
balansir-api        — HTTP/SSE API + WebUI serving
balansir-b4         — packet processing library
balansir-vpn        — VPN profile management
balansir-health     — unified path health model
balansir-ota        — OTA lifecycle (A/B slots, signing, rollback)
balansir-tests      — IPC integration tests
```

## Crate-by-Crate Status

### balansir-common (20 modules)

| Module | Status | Notes |
|--------|--------|-------|
| diff | CANONICAL | config diffing |
| error | CANONICAL | shared error types |
| event_bus | CANONICAL | bounded event bus |
| gateway | CANONICAL | GatewayConfig, validate(), DEFAULT_MGMT_PORTS |
| ipc | CANONICAL | postcard IPC, all MsgType variants dispatched |
| metrics | CANONICAL | SharedMetrics |
| network | CANONICAL | InterfaceInfo, WanIdentity |
| **path_pool** | **NEW** | PathPool, PathCandidate, SelectionStrategy — 8 tests |
| paths | CANONICAL | binary resolution |
| plan | CANONICAL | reconciliation plan types |
| profile | CANONICAL | VPN profile types |
| qos | CANONICAL | QoS config/result types |
| resources | CANONICAL | resource types |
| runtime | CANONICAL | runtime utils |
| snapshot | CANONICAL | shared snapshot |
| state | CANONICAL | state store |
| subsystems | CANONICAL | SubsystemSnapshot, SystemStats, FilesystemInfo, PathDecision |
| types | CANONICAL | HealthStatus, DriverId, etc |
| validation | CANONICAL | validation utilities |
| version | CANONICAL | version info |

### balansir-daemon (27 modules)

| Module | Status | Notes |
|--------|--------|-------|
| amneziawg | CANONICAL | WireGuard + AmneziaWG driver, wired via DriverFactory |
| b4 | CANONICAL | B4 driver, secrets integration |
| b4_dpi | CANONICAL | DPI engine, NFQUEUE, uses netlink |
| b4_engine | CANONICAL | B4 logic engine, state machine |
| b4_manager | CANONICAL | B4 lifecycle manager |
| capability | CANONICAL | CPU/RAM detection |
| dns | CANONICAL | DNS forwarder, SOCKS5 UDP relay, cache |
| dns_plane | CANONICAL | DNS observation plane |
| driver | CANONICAL | Driver lifecycle, Config, Factory |
| hysteria | CANONICAL | Hysteria2 driver, wired via DriverFactory |
| netlink | CANONICAL | netlink for DPI |
| **network_config** | **CANONICAL** | WAN/LAN role validation |
| **path_decision** | **UNWIRED** | Computed but only served as telemetry |
| **policy** | **UNWIRED** | PolicyConfig exists but engine not wired |
| reconciliation | CANONICAL | Reconciler, FlowCompiler, DnsRegistry |
| secrets | CANONICAL | secure file storage |
| server | CANONICAL | API server wiring |
| startup | CANONICAL | config loading |
| subsystems | CANONICAL | SubsystemManager, all subsystem wiring |
| system_stats | CANONICAL | /proc readers |
| upnp | CANONICAL | UPnP/IGD |
| vpn_manager | CANONICAL | VPN pool management |
| wan_identity | CANONICAL | WAN MAC detection |
| wireguard | CANONICAL | WireGuard driver |
| xray | CANONICAL | Xray config generation |
| xray_manager | CANONICAL | Xray lifecycle |

### balansir-executor (9 modules)

| Module | Status | Notes |
|--------|--------|-------|
| executor | CANONICAL | NftablesExecutor |
| gateway | CANONICAL | NAT, masquerade, management firewall |
| interface | CANONICAL | interface enumeration |
| **iprule** | **UNWIRED** | fwmark+ip-rule, tests pass, never instantiated |
| nftables | CANONICAL | nft command wrapper |
| path_mtu | CANONICAL | RouteMtuApplier (production), RecordOnlyApplier (test) |
| qdisc | CANONICAL | QoS tc operations |
| service | CANONICAL | NftablesExecutor, all ops dispatched |
| tailscale | CANONICAL | Tailscale operations |

### balansir-api (5 modules)

| Module | Status | Notes |
|--------|--------|-------|
| auth | CANONICAL | token auth |
| control | CANONICAL | ControlPlane, DesiredUpdater |
| handlers | CANONICAL | health, metrics, state endpoints |
| subsystems | CANONICAL | subsystem snapshot, /system endpoint, SSE |
| webui | CANONICAL | static file serving |

## Key Findings

### 1. path_decision is telemetry-only
- `decide()` is called in subsystems refresh
- Result stored in snapshot
- Served via `/path/decision` API
- **NOT consumed by any routing/policy engine**
- This is the correct design for now — routing uses direct B4/VPN checks

### 2. policy module is structural
- `PolicyConfig` exists in `b4_engine/policy.rs`
- Used by B4 manager for profile decisions
- No global policy engine that routes traffic through PathPool

### 3. iprule is ready but unwired
- Full implementation with tests
- Commented as "ready to wire when daemon contract can express mark↔table"
- Safe to keep

### 4. No duplicate implementations
- Single DNS: dns.rs forwarder + dns_plane.rs observation
- Single NAT/firewall: executor gateway backend
- Single nftables: executor nftables.rs
- Single policy: b4_engine/policy.rs (B4-specific)
- Single health: balansir-health crate

### 5. All IPC ops are dispatched
Every MsgType variant has executor dispatch + daemon client method.

### 6. Config fields are consumed
All config struct fields (DnsForwarderConfig, XrayConfig, etc.) are used.

### 7. Filesystems bug was real
The `/system` endpoint was returning empty Vec::new() instead of real filesystem data. Fixed in `78c132c`.

## Remaining Stubs

| Item | Location | Status |
|------|----------|--------|
| path_decision → routing | daemon/path_decision.rs | Telemetry only, not wired to routing |
| iprule backend | executor/iprule.rs | UNWIRED, ready |
| OTA retry limit | ota/slot.rs | Immediate rollback, no retry-before-rollback |
