# BalanSir Final Status

**Date**: 2026-08-17
**Last commit**: `2dd0db9` (HEAD, main)
**Commits this mission**: 17 commits (dead code cleanup, platform docs, API bind fix, BuildRoot fixes)

## Status Legend

| Status | Meaning |
|--------|---------|
| DONE | Code exists, compiles, wired, tested |
| VERIFIED | All of DONE + runtime/E2E verified |
| HARDWARE-BLOCKED | All of DONE but requires physical hardware for E2E |
| PARTIAL | Exists but incomplete or missing wiring |
| UNVERIFIED | Code exists but no runtime evidence |
| DEAD | Removed or documented as dead |

---

## Subsystem Status

### Gateway / NAT / Firewall
**Status**: DONE

- Commit `1a3dcdf`
- Explicit WAN/LAN roles from `NetworkConfig`
- Fail-closed validation (daemon starts only with valid roles)
- IP forwarding via `sysctl net.ipv4.ip_forward`
- Conntrack `established,related accept` + `invalid drop`
- MASQUERADE on WAN (`nat postrouting`)
- Management firewall (`filter input`, policy drop)
  - LAN → RPi: SSH(22), DNS(53), API(8080), metrics(9090) allowed
  - WAN → RPi: blocked by default policy
- Executor IPC (`GatewayOp`)
- Single canonical nftables owner

### DNS
**Status**: DONE

- Commit `98603ce` (canonical architecture), `ea82589` (SOCKS5 UDP), `3a88ef8` (actual Xray port)
- Single canonical listener (`dns.rs` forwarder)
- Classification: blocklist/allowlist with suffix matching, allowlist wins
- BLOCK path: local NXDOMAIN, no upstream, nft enforcement
- DIRECT path: normal upstream forwarding
- VPN path: `path_decision` → `XrayManagerHandle::socks_port()` → SOCKS5 UDP ASSOCIATE → Xray
- B4 path: `SwitchDnsPath` → `mark_adapting()` → `path_decision` shows `B4Adapting`
- Cache: `(domain, qtype)` key, bounded, TTL-based expiry
- No duplicate DNS subsystems

### B4 (Packet Processing)
**Status**: DONE

- Commit `e3574fb`
- TCP reassembly: 4-tuple, sequence tracking, duplicate/overlap handling, out-of-order, bounded memory
- Fragmented ClientHello: 1460+361 split, multiple fragments, gaps
- SNI extraction from reassembled TLS ClientHello
- FIN/RST cleanup, timeout/eviction
- B4 engine decisions: `AdaptMtu`, `SwitchDnsPath`, `Recovered`, `FailStrict`
- Path health integration: EMA smoothing, hysteresis, anti-flapping

### VPN / Xray
**Status**: DONE

- Commit `0e10e6f` (Xray 26.7.28 schema), `ea82589` (SOCKS5 UDP), `3a88ef8` (actual port)
- No generated `allowInsecure` in configs
- `pinnedPeerCertSha256` and `verifyPeerCertByName` supported
- XrayManagerHandle exposes actual `socks_port()`
- `path_decision` integration: when VPN active, DNS routes through SOCKS5 UDP
- Profile rotation via VPN pool
- Reality/TLS transport support

### UPnP/IGD
**Status**: DONE

- Commit `5664f4a`, `62c3fbd`
- LAN-only SSDP (239.255.255.250:1900)
- SOAP HTTP endpoint for Add/DeletePortMapping, GetExternalIPAddress, GetSpecificPortMappingEntry
- Source validation (LAN subnet only, reject loopback/multicast/WAN)
- Target validation (RFC1918/ULA only, reject public/zero)
- Lease/expiry/renewal mechanism
- Executor typed op (`UpnpOp`)
- nftables DNAT in `nat prerouting` chain
- WAN UPnP blocking

### System UI (btop-like)
**Status**: DONE

- Commits `24cc315`, `26b0ff5`
- Backend: `system_stats.rs` — real metrics from `/proc`
  - CPU: `/proc/stat` deltas
  - Memory: `/proc/meminfo`
  - Load: `/proc/loadavg`
  - Filesystems: `/proc/mounts` + `statfs(2)`
  - Network: `/proc/net/dev` deltas
  - Uptime: `/proc/uptime`
- Frontend: `System.svelte` with btop-inspired panels
- API: `GET /system`
- No stubs, no external btop dependency

### OTA
**Status**: DONE (unit), HARDWARE-BLOCKED (E2E)

- Ed25519 signing (`ed25519_dalek`)
- SHA-256 image verification
- Anti-rollback policy
- A/B slot management (`Slot::A` partition 2, `Slot::B` partition 3)
- `BootMetadata`: active_slot, next_slot, state, rollback_count
- Install: `dd` to partition, SHA-256 verify, set tryboot
- Health check: `HealthChecker::run()` with `should_confirm()` logic
- Rollback: automatic on health check failure, plus `force_rollback()`
- **Note**: No retry limit mechanism — immediate rollback on health failure. This is functional but differs from "retry N times then rollback".
- **RPi 3B+ boot chain**: Uses `config.txt` + `tryboot` mechanism
- **E2E requires physical RPi 3B+ hardware**

### IpRule (fwmark + policy routing)
**Status**: UNWIRED

- Implementation exists in `iprule.rs` with tests
- Never instantiated in production (comment only in `service.rs`)
- Ready to wire when daemon policy engine emits fwmark+table pairs

### BuildRoot
**Status**: VERIFIED

- BuildRoot configuration exists in `buildroot-external/`
- QEMU builder at `/home/builder/br-qemu`
- Sync script: `./deploy/buildroot/sync-to-vm.sh 2222`
- Build command: `make balansir-rebuild all`
- **Image verified**: 2GB sdcard.img with MBR partition table
  - boot.vfat (64MB, FAT32, bootable)
  - system-A.ext4 (300MB) with daemon/executor/cli/systemd
  - system-B.ext4 (300MB, empty, OTA target)
  - persistent.ext4 (1.3GB, empty)
- SHA256: `75d474a9eb2e00e06dd6fd59c27147d652beec94a129132e41ecc349be00e58d`
- Rootfs contents verified: daemon, executor, CLI, systemd services, WebUI

### RPi 3B+ Deployment
**Status**: HARDWARE-BLOCKED

- SD card image generated: `/home/builder/br-qemu/images/sdcard.img` (2.0GB)
- Partition table verified via `fdisk -l`
- Rootfs mounted and verified: daemon/executor/cli/WebUI present
- **E2E requires physical RPi 3B+ hardware**
- First boot: `192.168.3.2`, WebUI on `:8080`, SSH on `:22`

---

## Architecture Verification

### Single Canonical Owner
- ✅ nftables: executor only
- ✅ DNS: single `dns.rs` forwarder + `dns_plane.rs` observation
- ✅ NAT/firewall: single executor gateway backend
- ✅ Policy: single `policy/` module
- ✅ Interface operations: executor only

### Privilege Boundary
- ✅ Daemon (unprivileged) → IPC → Executor (privileged) → kernel
- ✅ Daemon never touches nftables directly
- ✅ Daemon never accesses raw block devices

### Dead Code Cleanup
- ✅ `path_health.rs` in balansir-common: removed (dead duplicate)
- ✅ `bootstrap.rs` in reconciliation: removed (never called)
- ✅ `iprule.rs`: documented as UNWIRED, kept as ready implementation
- ✅ No duplicate DNS/NAT/firewall/policy implementations

### Platform Portability
- ✅ No incorrect RPi hardcodes in production Rust code
- ✅ All `eth0`/`192.168.3.2`/WAN MAC occurrences are test-only
- ✅ OTA partition scheme is RPi-specific by design (correct boundary)
- ✅ All `/proc` and `/sys` paths are generic Linux

### LAN Management
- ✅ Firewall: LAN → {22, 53, 8080, 9090} allowed, WAN → blocked
- ✅ API: configurable bind address (default `127.0.0.1:8080`, set to `0.0.0.0:8080` for LAN)
- ✅ DNS: configurable listen address
- ✅ SSH: systemd service on port 22
- ⚠️ Deployment note: must configure `BALANSIR_API_BIND=0.0.0.0:8080` for LAN WebUI/API access
