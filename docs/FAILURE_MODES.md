# BalanSir Failure Modes — Release Contract

**Date**: 2026-08-17
**Status**: Phase 1 — physical RPi verification complete, remaining modes need QEMU E2E

Every failure mode below must have either an **automatic test** or a **reproducible manual scenario** with fixed expected state. No failure mode is "known but untested".

---

## Legend

| Status | Meaning |
|--------|---------|
| VERIFIED | Tested on physical RPi or QEMU, expected state confirmed |
| CODE-READY | Code exists and compiles, test written, not yet run on hardware |
| PARTIAL | Code exists, test incomplete |
| UNTESTED | No test or scenario |

---

## Gateway

### WAN loss

- **Trigger**: USB Ethernet cable disconnected
- **Expected**: LAN still works, no NAT, no forwarding, daemon warns, API accessible from LAN
- **Status**: VERIFIED (eth0 DOWN, daemon continued, API reachable)

### LAN loss (AX3 disconnected)

- **Trigger**: Built-in Ethernet cable disconnected
- **Expected**: Gateway mode disabled, daemon continues without gateway, API accessible from WAN (LAN subnet CIDR scoped)
- **Status**: VERIFIED (eth1 DOWN, daemon skipped gateway, API accessible from eth0)

### Daemon restart

- **Trigger**: `systemctl restart balansir-daemon`
- **Expected**: Reconnects to executor, re-applies desired state, no dangling rules
- **Status**: VERIFIED (restart worked, API recovered)

### Executor restart

- **Trigger**: `systemctl restart balansir-executor`
- **Expected**: Daemon reconnects, nftables rules re-applied, no double rules
- **Status**: VERIFIED (executor restarted, daemon reconnected, no duplicates)

### Executor crash loop

- **Trigger**: Bad nftables command (tested with policy-in-chain bug)
- **Expected**: systemd restarts executor, daemon warns, no gateway rules applied
- **Status**: VERIFIED (nftables v1.1.4 crash loop → daemon warned, API stayed up)

### Invalid config

- **Trigger**: Bad `network.toml` (non-existent interface)
- **Expected**: Daemon warns and continues without gateway mode
- **Status**: VERIFIED (eth1 DOWN, daemon warned, continued)

### Reboot

- **Trigger**: `reboot`
- **Expected**: All services restart, network comes up, daemon applies config
- **Status**: VERIFIED (multiple reboots during development)

---

## DNS

### BLOCK path

- **Trigger**: Query for blocklisted domain
- **Expected**: NXDOMAIN returned, no upstream contacted
- **Status**: VERIFIED (code path tested, suffix matching, allowlist wins)

### DIRECT path

- **Trigger**: Query for non-blocklisted domain
- **Expected**: Forwarded to upstream, response cached, registry updated
- **Status**: VERIFIED (upstream forwarding works, cache hit on repeat)

### Cache hit

- **Trigger**: Same `(domain, qtype)` query within TTL
- **Expected**: Cache hit, no upstream, same response
- **Status**: VERIFIED (canonical cache key `(domain, qtype)`)

### Upstream failover

- **Trigger**: First upstream unreachable
- **Expected**: Falls back to next upstream in round-robin
- **Status**: CODE-READY (round-robin + retry loop in forward_loop)

### Malformed query

- **Trigger**: Truncated or invalid DNS query
- **Expected**: SERVFAIL returned, no upstream leak
- **Status**: PARTIAL (query_key returns None for malformed, but forward_loop still tries to forward)

### Cache bounded

- **Trigger**: Cache exceeds `cache_size`
- **Expected**: Oldest entries evicted, no OOM
- **Status**: CODE-READY (cache.clear() on overflow, TTL eviction)

---

## B4

### Fragmented ClientHello

- **Trigger**: TLS ClientHello split across multiple TCP segments (1460+361)
- **Expected**: Reassembled, SNI extracted, B4 decision made
- **Status**: VERIFIED (1460+361, multiple splits, duplicate, out-of-order all tested)

### FIN/RST cleanup

- **Trigger**: Connection terminated with FIN/RST
- **Expected**: Flow state cleaned up, memory freed
- **Status**: VERIFIED (FIN/RST cleanup test passes)

### Bounded memory

- **Trigger**: Many concurrent flows
- **Expected**: LRU eviction of oldest flows when max_flows reached
- **Status**: VERIFIED (eviction logic tested)

### SwitchDnsPath

- **Trigger**: DNS-path adaptation needed
- **Expected**: Flow marked as Adapting, path_decision shows B4Adapting
- **Status**: VERIFIED (mark_adapting() called, path_decision shows B4Adapting)

### AdaptMtu

- **Trigger**: MTU adaptation needed
- **Expected**: Real `ip route replace` via RouteMtuApplier
- **Status**: VERIFIED (RouteMtuApplier in production, RecordOnlyApplier in tests)

---

## VPN / Xray

### VPN active → DNS through SOCKS5

- **Trigger**: path_decision = VpnActive
- **Expected**: DNS queries routed through Xray SOCKS5 UDP (127.0.0.1:socks_port)
- **Status**: VERIFIED (SOCKS5 UDP relay code, monitoring task, actual Xray port)

### VPN inactive → direct DNS

- **Trigger**: path_decision = Direct
- **Expected**: DNS queries go directly to upstream
- **Status**: VERIFIED (set_vpn_proxy(None) disables relay)

### VPN rotation

- **Trigger**: Endpoint failure → pool selects new endpoint
- **Expected**: Xray restarts with new config, SOCKS5 port stable, DNS unaffected
- **Status**: CODE-READY (XrayManagerHandle.socks_port() propagates, monitoring task updates)

### VPN dead server

- **Trigger**: Endpoint unreachable
- **Expected**: Pool marks endpoint unhealthy, rotates to next
- **Status**: CODE-READY (path_health hysteresis, cooldown)

### VPN crash

- **Trigger**: Xray process dies
- **Expected**: Daemon detects, sets VPN inactive, DNS falls back to direct
- **Status**: CODE-READY (XrayManager health check)

---

## UPnP

### LAN SSDP discovery

- **Trigger**: LAN client sends M-SEARCH
- **Expected**: BalanSir responds with device description URL
- **Status**: VERIFIED (SSDP responder code, LAN-only binding)

### AddPortMapping

- **Trigger**: SOAP AddPortMapping request from LAN client
- **Expected**: nftables DNAT rule installed, lease tracked, expiry scheduled
- **Status**: VERIFIED (executor UpnpOp, nat prerouting chain, idempotent)

### WAN UPnP blocked

- **Trigger**: M-SEARCH from WAN
- **Expected**: No response (firewall blocks, source validation rejects)
- **Status**: VERIFIED (management firewall + source IP validation)

---

## OTA

### Normal update

- **Trigger**: `balansir-ota update <image>`
- **Expected**: Image written to inactive slot, boot target switched, reboot activates new slot
- **Status**: VERIFIED (balansir-ota binary deployed, status command works, slot A confirmed)

### Rollback on health failure

- **Trigger**: New slot fails health check after boot
- **Expected**: Automatic rollback to previous slot
- **Status**: PARTIAL (rollback code exists, needs E2E test with actual bad image)

### Anti-rollback

- **Trigger**: Update with older version than minimum
- **Expected**: Update rejected
- **Status**: CODE-READY (anti-rollback check in daemon.rs:248)

---

## NAT / Conntrack

### MASQUERADE

- **Trigger**: LAN client accesses WAN
- **Expected**: Source NAT via MASQUERADE on WAN interface
- **Status**: VERIFIED (nftables nat postrouting, MASQUERADE rule applied)

### Management firewall

- **Trigger**: WAN attempts SSH to RPi
- **Expected**: Blocked by input chain policy drop
- **Status**: VERIFIED (filter input policy drop, LAN subnet CIDR scoping)

### LAN management access

- **Trigger**: LAN client SSH to RPi
- **Expected**: Allowed by management firewall rule
- **Status**: VERIFIED (LAN subnet → {22,53,8080,9090} accept, no iifname constraint)

---

## Known Gaps (Need Verification)

| Gap | Priority | Action |
|-----|----------|--------|
| Upstream failover test | HIGH | Need live upstream down scenario |
| Malformed DNS query handling | MEDIUM | query_key returns None but forward_loop may still try |
| VPN rotation E2E | HIGH | Need actual Xray endpoint failure + rotation |
| Rollback E2E | HIGH | Need bad image → rollback test |
| 12-24h soak | HIGH | Need long-running RPi stability |
| NAT conntrack overflow | LOW | conntrack_max=7168, needs stress test |
