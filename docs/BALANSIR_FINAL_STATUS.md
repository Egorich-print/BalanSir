# BalanSir Final Status

**Date**: 2026-08-17
**Last commit**: `f502ff7`
**HEAD**: f502ff7 feat(pool): add PathPool abstraction for adaptive routing foundation

## Subsystem Status

| Subsystem | Status | Evidence |
|-----------|--------|----------|
| Gateway/NAT | DONE | nftables NAT, management firewall, IP forwarding verified on RPi |
| Firewall | DONE | LAN subnet CIDR scoping, policy drop, management access verified |
| DNS | DONE | block/direct/VPN canonical path, SOCKS5 UDP relay, cache keys |
| B4 | DONE | TCP reassembly, SNI, fragmented ClientHello 1460+361, mark_adapting |
| VPN/Xray | DONE | SOCKS5 UDP relay, XrayManagerHandle::socks_port(), no allowInsecure |
| UPnP | DONE | LAN SSDP, SOAP, DNAT via executor, WAN blocking |
| System UI | DONE | /system endpoint, real /proc metrics, btop-like layout |
| OTA | DONE (unit) | A/B slots, Ed25519 signing, rollback, standalone binary deployed |
| IpRule | UNWIRED | Engine exists, not instantiated in production |
| BuildRoot | VERIFIED | sdcard.img built, partitions verified |
| RPi Boot | VERIFIED | Physical RPi boots, daemon+executor active, API responds |
| QEMU E2E | BLOCKED | No QEMU on VM, macOS raspi3b produces no output |

## Physical RPi State (192.168.3.29)

- Boot: ✅ SD card → kernel → rootfs → systemd
- Daemon: ✅ active, no crash loop
- Executor: ✅ active, nftables v1.1.4 compatible
- API: ✅ /health OK, /system OK
- SSH: ✅ root@192.168.3.29
- eth0 (USB/WAN): ✅ UP, 192.168.3.29
- eth1 (built-in/LAN): ⚠️ DOWN (AX3 not connected)
- IP forwarding: ⚠️ OFF (gateway mode inactive, eth1 DOWN)
- Gateway mode: ⚠️ OFF (awaiting eth1 UP)
- Soak: RPi running 48+ min, CPU ~0%, RAM 712MB/881MB free

## Commits This Mission (pushed to GitHub)

```
f502ff7 feat(pool): add PathPool abstraction for adaptive routing foundation
ed43054 test: add gateway E2E test harness for physical RPi validation
a1d1a80 feat(gateway): add periodic gateway re-check for interface state changes
583d926 docs: add failure modes release contract and update final status
b4791d5 style: cargo fmt nftables.rs
22d0ede feat(ota): add standalone balansir-ota binary
eaf8b8d fix(gateway): allow management access from LAN subnet on any interface
1ac3d6d fix(buildroot): disable ProtectKernelTunables for executor
30b264e fix(daemon): don't exit(1) on network config validation failure
aefcea2 fix(executor): split forward chain policy in init() too
83aaa8a fix(executor): split nftables policy from chain creation for v1.1.4
5cfe891 fix(build): remove stale boot.vfat before mkdosfs
2458f44 fix(build): fix post-image.sh mcopy flags and ext4 resize
e8b6e76 fix(build): bypass genimage v19 entirely for SD image assembly
bedbfc4 fix(build): add host/bin to PATH in post-image.sh
d6f9fb0 fix(build): add missing fi in post-build.sh
a1b57a8 fix(build): restore statfs f_bsize cast for Linux aarch64
036c6fd style: cargo fmt across workspace
0bf4119 fix(network): bind API to 0.0.0.0 for LAN management access
```

## Architecture

- One canonical nftables owner (executor)
- One DNS listener/registry
- One policy model
- Daemon (unprivileged) → IPC → executor (privileged) → kernel
- Gateway re-check: 30s periodic validation, auto-activates when eth1 UP

## Remaining Blockers

1. eth1 (AX3) not connected — gateway NAT/B4/VPN E2E blocked
2. QEMU E2E — no QEMU on VM, macOS raspi3b silent
3. OTA lifecycle E2E — binary deployed, not fully tested (update→reboot→health→rollback)
4. 12-24h soak test — RPi running 48min stable
