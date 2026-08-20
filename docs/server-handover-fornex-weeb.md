# Server Handover & Architecture Specification: Fornex Weeb Node (`fornex-weeb`)

> **Date:** August 7, 2026  
> **Target Node:** `weeb.twilightparadox.com` (`199.68.199.68`)  
> **Project:** BalanSir (Policy-Based Network Execution Engine)  
> **Profile:** `config/profiles/fornex-weeb.toml`

---

## 1. Executive Summary

This document provides a complete technical handover for the production VPN/DNS runtime node deployed on Fornex (`199.68.199.68`). The node has undergone a full destructive reset of legacy configurations and has been rebuilt from scratch as a **BalanSir-ready node**. It hosts 5 independent transport stacks across 20 provisioned client devices, managed via Tailscale and AdGuardHome.

---

## 2. Server Identity & Access

| Parameter | Value |
|---|---|
| **Hostname / Domain** | `weeb.twilightparadox.com` (managed via FreeDNS) |
| **Public IPv4** | `199.68.199.68` |
| **Tailscale IP** | `100.95.185.77` |
| **SSH Access** | `sshpass -p "REDACTED-FORNEX-SSH-PASSWORD" ssh root@100.95.185.77` (or via public IP) |
| **OS / Kernel** | Ubuntu 24.04.4 LTS (Linux 6.8.0-136-generic x86_64) |
| **Hardware Specs** | 961 MB RAM, ~2.3 GB free disk space (`/dev/vda1`) |

---

## 3. Network Topology & Port Allocation

```text
                                Internet
                                   │
                    ┌──────────────┴──────────────┐
                    │      199.68.199.68          │
                    └──────┬──────┬──────┬────────┘
                           │      │      │
                        443/TCP  443/UDP 51820/UDP
                           │      │      │
                         Xray    AWG3   AWG2
                           │      │      │
                           └──────┼──────┘
                                  │
                               BalanSir
                                  │
                         ┌────────┴────────┐
                         │                 │
                    VPN policy        DNS policy
                         │                 │
                         │            AdGuardHome
                         │                 │
                         └────────┬────────┘
                                  │
                              Tailscale
                             (Management)
```

### Active Listeners & Bindings
- **SSH (`22/tcp`)**: `0.0.0.0:22`
- **Tailscale (`41641/udp`, `38979/tcp`)**: `100.95.185.77`
- **Xray VLESS+Reality (`443/tcp`)**: `0.0.0.0:443` (XHTTP transport, SNI `www.microsoft.com`)
- **Xray VLESS+Reality (`2087/tcp`)**: `0.0.0.0:2087` (gRPC transport, SNI `www.apple.com`)
- **AmneziaWG 3.0 (`443/udp`)**: Docker container `awg3`, subnet `10.8.3.0/24`, gateway `10.8.3.1`
- **AmneziaWG 2.0 (`51820/udp`)**: Docker container `amnezia-awg2`, subnet `10.8.2.0/24`, gateway `10.8.2.1`
- **Hysteria 2.0 (`3658/udp`)**: Docker container `hysteria2`
- **AdGuardHome DNS (`53/udp+tcp`)**: Bound strictly to `127.0.0.1`, `100.95.185.77`, `10.8.3.1`, `10.8.2.1`. **WAN port 53 is closed.**
- **AdGuardHome Web UI (`8080/tcp`)**: Bound to `100.95.185.77:8080` (Tailscale only).

---

## 4. Active VPN Stacks & Parameters

### Stack 1: VLESS + XHTTP + Reality (Primary L7)
- **Engine:** Xray-core v26.3.27 (native systemd service `xray.service`)
- **Port / Transport:** `443/tcp`, `xhttp` network (`mode: auto`), flow `xtls-rprx-vision`
- **Reality Settings:** `dest: "www.microsoft.com:443"`, SNI `www.microsoft.com`, fingerprint `chrome`
- **XMUX:** `maxConcurrency: "1-6"` (anti-TSPU behavior optimization)

### Stack 2: VLESS + gRPC + Reality (Backup L7)
- **Engine:** Xray-core v26.3.27 (`inbound-grpc`)
- **Port / Transport:** `2087/tcp`, `grpc` network, SNI `www.apple.com`

### Stack 3: AmneziaWG 3.0 (Primary L3)
- **Engine:** `vaiprog/amnezia-wg-3:latest` (userspace `amneziawg-go` inside Docker)
- **Port:** `443/udp`
- **Subnet:** `10.8.3.0/24`, Gateway `10.8.3.1`
- **Obfuscation:** `Jc=4`, `Jmin=40`, `Jmax=100`, `S1=36`, `S2=52`, `H1–H4` set.

### Stack 4: AmneziaWG 2.0 (Secondary L3)
- **Engine:** `vaiprog/amnezia-wg-3:latest` (`amnezia-awg2`)
- **Port:** `51820/udp`
- **Subnet:** `10.8.2.0/24`, Gateway `10.8.2.1`
- **Obfuscation (decorrelated):** `Jc=2`, `Jmin=20`, `Jmax=50`, `S1=22`, `S2=28`, distinct `H1–H4`.

### Stack 5: Hysteria 2.0
- **Engine:** Hysteria 2 Docker container
- **Port:** `3658/udp`
- **Auth:** Shared password (`REDACTED-HYSTERIA-PASSWORD`)

---

## 5. Provisioned Devices (20 Clients)

All 20 devices have fully generated credentials for all stacks, stored in `/Users/egorich/Documents/vpn-node-weeb/keys.md`:
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

## 6. BalanSir Integration Roadmap (Next Steps for Next Agent)

1. **Profile Utilization:** The node profile exists at `config/profiles/fornex-weeb.toml`.
2. **Driver Mapping to BalanSir Architecture:**
   - `XrayServerDriver` (manages `/usr/local/etc/xray/config.json`)
   - `AmneziaWGUserspaceDriver` (manages Docker containers `awg3` and `amnezia-awg2`)
   - `AdGuardHomeDriver` (manages `/opt/AdGuardHome/AdGuardHome.yaml`)
3. **Secrets Management:** Ensure runtime secrets comply with **ADR-006** (`/run/balansir/<driver>-<id>.json` with `0600` permissions and memory wipe on Drop).
4. **Daemon Deployment (Future):** Once BalanSir daemon is ready for production rollout on low-RAM nodes, deploy `balansir-daemon` and `balansir-executor` with restricted capabilities and root-gated IPC socket at `/run/balansir/daemon.sock`.
