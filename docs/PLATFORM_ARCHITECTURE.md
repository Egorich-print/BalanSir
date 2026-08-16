# BalanSir Platform Architecture

**Date**: 2026-08-17

## Architecture Layers

```
┌─────────────────────────────────────────────┐
│  Generic Rust/Linux Core                    │
│  (all crates except buildroot-external)     │
│                                             │
│  • No RPi-specific assumptions              │
│  • Interface names from config/runtime      │
│  • /proc and /sys are generic Linux         │
│  • OTA partition scheme is configurable     │
└─────────────┬───────────────────────────────┘
              │
┌─────────────┴───────────────────────────────┐
│  Platform Abstractions                      │
│                                             │
│  • NetworkConfig: WAN/LAN roles (config)    │
│  • InterfaceInfo: runtime interface scan    │
│  • CapabilityProfile: hardware detection    │
│  • NftablesBackend: nft command interface   │
│  • RouteMtuApplier: ip route commands       │
│  • All paths use dynamic resolution         │
└─────────────┬───────────────────────────────┘
              │
┌─────────────┴───────────────────────────────┐
│  BuildRoot / Target Board Layer             │
│  (buildroot-external/)                      │
│                                             │
│  • RPi 3B+ defconfig                        │
│  • post-image-ota.sh: partition layout      │
│  • rootfs-overlay: target config files      │
│  • systemd units                            │
│  • DTB, kernel config                       │
│  • Target-specific only here                │
└─────────────────────────────────────────────┘
```

## Findings by Category

### Generic Linux (no platform coupling)

| Component | Path(s) | Notes |
|-----------|---------|-------|
| CPU detection | `/sys/devices/system/cpu/possible` | Generic Linux sysfs |
| Memory detection | `/proc/meminfo` | Generic Linux procfs |
| Load averages | `/proc/loadavg` | Generic Linux procfs |
| Filesystems | `/proc/mounts` + `statfs(2)` | Generic Linux, virtual FS filtered |
| Network counters | `/proc/net/dev` | Generic Linux procfs |
| Interface scan | `/sys/class/net/*` | Generic Linux sysfs |
| IP forwarding | `/proc/sys/net/ipv4/ip_forward` | Generic Linux procfs |
| nftables | `nft` binary (dynamic path) | Generic Linux, resolved at runtime |
| ip route | `ip` binary (dynamic path) | Generic Linux, resolved at runtime |
| CPU capability | CPUID-based detection | Generic aarch64/x86_64 |
| Module detection | `/proc/modules` | Generic Linux |

### Platform Adapter (configurable)

| Component | Configuration | Notes |
|-----------|---------------|-------|
| WAN interface | `NetworkConfig.wan_interface` | Config-driven, not hardcoded |
| LAN interface | `NetworkConfig.lan_interface` | Config-driven, not hardcoded |
| LAN subnet | `NetworkConfig.lan_subnet` | Config-driven, default 192.168.3.0/24 |
| WAN MAC | `NetworkConfig.wan_mac` | Config-driven, optional |
| Xray SOCKS port | `XrayConfig.socks_port` | Config-driven, default 10808 |
| DNS listen | `DnsForwarderConfig.listen` | Config-driven |
| DNS upstreams | `DnsForwarderConfig.upstreams` | Config-driven |
| OTA partition | `METADATA_PATH` | Config-driven |
| API listen | `BALANSIR_API_PORT` | Environment variable |

### BuildRoot Target Config (RPi 3B+ specific)

| Component | File | Notes |
|-----------|------|-------|
| Partition layout | `post-image-ota.sh` | `/dev/mmcblk0p1-4` |
| Boot cmdline | `post-image-ota.sh` | `root=/dev/mmcblk0p2` |
| DTB | `bcm2710-rpi-3-b-plus.dtb` | RPi 3B+ only |
| Kernel | `kernel8.img` | RPi 3B+ aarch64 |
| Default network | `network.toml` overlay | Example config with eth0 |
| systemd services | `balansir-daemon.service` | Service unit |
| `192.168.3.2` | Test code only | Not in production Rust |
| `90:98:38:52:AE:79` | Test code only | Not in production Rust |
| `/boot` | OTA constant | RPi boot partition |
| `/persistent` | OTA constant | RPi persistent storage |

## Portability Assessment

### Currently portable to any Linux gateway

- Gateway/NAT/firewall: any Linux with nftables
- DNS: any Linux with UDP socket support
- B4: any Linux with NFQUEUE
- VPN/Xray: any Linux with tun support
- UPnP: any Linux with UDP sockets
- System monitoring: any Linux with /proc
- QoS: any Linux with tc
- API/WebUI: any Linux with tokio

### Requires per-platform work

- **OTA boot chain**: RPi 3B+ uses `config.txt` + `tryboot`. Other boards have different boot mechanisms.
- **Partition layout**: `/dev/mmcblk0p2`/`p3` is RPi-specific. x86 uses `/dev/sda2`/`sda3`.
- **DTB**: RPi-specific. Other ARM boards have different DTBs.

### NOT portable without modification

- `post-image-ota.sh`: RPi 3B+ partition script
- OTA slot detection (`cmdline.txt` parsing for `balansir_slot`)

## Conclusion

BalanSir core is **generic Linux** with no incorrect RPi hardcodes. The only RPi-specific code is in the OTA crate (partition scheme, boot chain) and BuildRoot configs (DTB, partition layout, default network). This is the correct architectural boundary.
