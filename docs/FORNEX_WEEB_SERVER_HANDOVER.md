# Handover: Fornex Weeb VPS Node (`199.68.199.68`)

> **Date:** August 7, 2026  
> **Target Project:** BalanSir (`/Users/egorich/ai-workstation/Projects/BalanSir`)  
> **Server Node:** `weeb.twilightparadox.com` (`199.68.199.68`)

---

## 1. Server Identity & Access

| Parameter | Value |
|---|---|
| **Hostname** | `297203.fornex.cloud` |
| **Public IPv4** | `199.68.199.68` |
| **Domain (FreeDNS)** | `weeb.twilightparadox.com` |
| **Tailscale IP** | `100.95.185.77` |
| **SSH Access** | `root` @ `199.68.199.68` |
| **SSH Password** | `A6Oo6bVvsB41B6Qt` |
| **OS / Kernel** | Ubuntu 24.04.4 LTS (x86_64, Linux 6.8.0-136-generic) |
| **Hardware** | 961 MB RAM, ~2.3 GB free disk space, 1 CPU core |

---

## 2. Network & Kernel Tuning

- **IP Forwarding:** Enabled (`net.ipv4.ip_forward = 1`)
- **Congestion Control:** BBR + `fq` qdisc (`net.ipv4.tcp_congestion_control = bbr`, `net.core.default_qdisc = fq`)
- **Buffers:** `net.core.rmem_max` / `wmem_max` = 134MB
- **Management Plane:** Tailscale (`tailscale0` interface, active)

---

## 3. Deployed VPN & DNS Stacks (5 Independent Protocols)

All legacy VPN configurations and old keys have been completely wiped. The current state is a clean, production-ready VPN/DNS runtime.

### A. DNS Plane: AdGuardHome
- **Role:** Centralized DNS resolver and ad-blocker for all VPN subnets and Tailscale clients.
- **Listeners:**
  - `127.0.0.1:53` (local)
  - `100.95.185.77:53` (Tailscale)
  - `10.8.3.1:53` (AmneziaWG 3 gateway)
  - `10.8.2.1:53` (AmneziaWG 2 gateway)
- **Web UI:** `http://100.95.185.77:8080` (Username: `egorich`)
- **Security:** External WAN port 53 is strictly closed (no open resolver).

### B. VLESS + XHTTP + Reality (Proxy #1)
- **Port:** `443/tcp`
- **SNI / Dest:** `www.microsoft.com:443`
- **Transport:** `xhttp`, mode `auto`, random path
- **Flow:** `xtls-rprx-vision`
- **XMUX Limit:** `maxConcurrency: "1-6"` (bypasses behavioral TSPU heuristic)
- **PrivateKey (Server):** `YPRsZbEb8eVV-82E-mf_Xw24KwnJkSmV4UTZgKGhIWc`
- **PublicKey:** `CIhNiKnj7U5TAub1Fw12F73T1bjWUyQVC6fcv5jnEgI`
- **ShortId:** `77e1df3b17f774f3`

### C. VLESS + gRPC + Reality (Proxy #2)
- **Port:** `2087/tcp`
- **SNI / Dest:** `www.apple.com:443`
- **Transport:** `grpc`, serviceName `AppleService`
- **Flow:** None (standard gRPC mode)

### D. AmneziaWG 3.0 (L3 Tunnel #1)
- **Port:** `443/udp`
- **Subnet:** `10.8.3.0/24`, Gateway: `10.8.3.1`
- **Runtime:** Docker container `awg3` (`vaiprog/amnezia-wg-3:latest`)
- **Obfuscation:** `H1=919582908`, `H2=1745662034`, `H3=896377387`, `H4=381682041`, `S1=36`, `S2=52`, `S3=55`, `S4=12`, `Jc=6`, `Jmin=34`, `Jmax=150`, HeaderProtectionKey enabled.

### E. AmneziaWG 2.0 (L3 Tunnel #2)
- **Port:** `51820/udp`
- **Subnet:** `10.8.2.0/24`, Gateway: `10.8.2.1`
- **Runtime:** Docker container `amnezia-awg2` (`vaiprog/amnezia-wg-3:latest`)
- **Obfuscation:** Decorrelated parameters (`H1=123456789`, `S1=40`, `S2=48`, `Jc=4`, etc.).

### F. Hysteria 2.0 (High-Speed Proxy)
- **Port:** `3658/udp`
- **Auth:** Password-based (`/etc/hysteria/config.yaml`)
- **Runtime:** Systemd service `hysteria-server` (`/usr/local/bin/hysteria`)
- **Masquerade:** `https://www.microsoft.com`

---

## 4. Provisioned Devices (20 Devices)

Configs and links for all 20 devices across all 5 protocols are stored in:
- Local: `/Users/egorich/Documents/vpn-node-weeb/keys.md`
- Remote: `/root/output/keys.md`

**Device list:**
1. `Egorich-macbook`
2. `Egorich-mobile`
3. `Egorich-asus`
4. `Egorich-guest`
5. `Luiza-mobile`
6. `Luiza-ipad`
7. `Tatiana-mobile`
8. `Natasha-mobile`
9. `Maxim-mobile`
10. `Maxim-pc`
11. `Maxim-macbook`
12. `Sasha-1`
13. `Sasha-2`
14. `Sasha-3`
15. `Zikrat-laptop`
16. `Zikrat-mobile`
17. `Vasya-pc`
18. `Vasya-mobile`
19. `Twin-mobile`
20. `Twin-macbook`

---

## 5. BalanSir Integration Status

- **Server Profile Created:** `config/profiles/fornex-weeb.toml` (reflects 961 MB RAM, 1 CPU, 4 max active drivers).
- **Next Architectural Steps for BalanSir:**
  1. Map `ComponentDriver` traits to existing runtime binaries/containers (`XrayServerDriver`, `AmneziaWGUserspaceDriver`, `AdGuardHomeDriver`).
  2. Enforce ADR-006 secrets path: `/run/balansir/<driver>-<id>.json` with mode `0600`.
  3. Keep the control plane decoupled (do not install full daemon on this 1GB RAM node until lightweight execution target is ready).
