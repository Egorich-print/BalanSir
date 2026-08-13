# BalanSir — Fornex Weeb Node Specification & Handover Blueprint

> **Node ID:** `fornex-weeb`
> **Public IP:** `199.68.199.68`
> **Domain (FreeDNS):** `weeb.twilightparadox.com`
> **Tailscale IP:** `100.95.185.77`
> **OS:** Ubuntu 24.04.4 LTS (Linux 6.8.0-136-generic x86_64)
> **Resources:** 961 MB RAM, ~2.3 GB free disk (`/dev/vda1` 9.8G)
> **Status:** Fully provisioned, clean baseline, BalanSir-ready.

---

## 1. Network Topology & Port Allocation

```text
                             Internet
                                │
                    ┌───────────┴───────────┐
                    │   199.68.199.68       │
                    └───────────┬───────────┘
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
       443/TCP               2087/TCP             3658/UDP
          │                     │                     │
   Xray (XHTTP)          Xray (gRPC)            Hysteria 2.0
          │                     │                     │
       443/UDP              51820/UDP              53/UDP (Local)
          │                     │                     │
        AWG 3                AWG 2             AdGuardHome
      (10.8.3.0/24)        (10.8.2.0/24)      (DNS for VPN)
          │                     │                     │
          └─────────────────────┴─────────────────────> Tailscale (100.95.185.77)
```

| Port / Proto | Service | Driver Mapping (BalanSir) | Notes |
|---|---|---|---|
| `22/tcp` | SSH | Management | Root access via password / SSH key |
| `41641/udp` | Tailscale | Management Plane (`tailscaled`) | Overlay mesh network |
| `53/udp+tcp` | AdGuardHome | DNS Plane (`DnsForwarderDriver`) | Bound to `127.0.0.1`, `100.95.185.77`, `10.8.3.1`, `10.8.2.1`. **WAN blocked.** |
| `8080/tcp` | AdGuardHome UI | Management UI | Bound to `100.95.185.77:8080` (Tailscale only) |
| `443/tcp` | Xray (XHTTP) | `XrayDriver` (Layer 7) | VLESS + XHTTP + Reality (SNI `www.microsoft.com`, Vision, XMUX 1-6) |
| `2087/tcp` | Xray (gRPC) | `XrayDriver` (Layer 7) | VLESS + gRPC + Reality (SNI `www.apple.com`) |
| `443/udp` | AmneziaWG 3.0 | `AmneziaWGDriver` (Layer 3) | Userspace `amneziawg-go`, subnet `10.8.3.0/24` |
| `51820/udp` | AmneziaWG 2.0 | `AmneziaWGDriver` (Layer 3) | Userspace `amneziawg-go`, subnet `10.8.2.0/24` |
| `3658/udp` | Hysteria 2.0 | `HysteriaDriver` (Layer 7) | Password auth, masquerade proxy |

---

## 2. Component Specifications & Runtime Details

### 2.1 Management & DNS Plane
- **Tailscale:** Active (`100.95.185.77`), provides secure out-of-band management and WebUI access.
- **AdGuardHome:** Installed at `/opt/AdGuardHome/AdGuardHome`, systemd service `AdGuardHome.service`. Configured to handle DNS requests from all VPN subnets (`10.8.3.1`, `10.8.2.1`) and Tailscale clients. Upstream: Cloudflare/Quad9 DoH.

### 2.2 Layer 7 Proxy Drivers (Xray & Hysteria)
- **Xray Core (`/usr/local/bin/xray`, v26.3.27):**
  - Managed via systemd `xray.service`.
  - Config: `/usr/local/etc/xray/config.json`.
  - Inbound 1 (`443/tcp`): VLESS, network `xhttp`, security `reality`, dest `www.microsoft.com:443`, flow `xtls-rprx-vision`, XMUX maxConcurrency `1-6`.
  - Inbound 2 (`2087/tcp`): VLESS, network `grpc`, security `reality`, dest `www.apple.com:443`, serviceName `weebgrpc`.
- **Hysteria 2 (`apernet/hysteria:latest` docker container):**
  - Port `3658/udp`.
  - Config: `/etc/hysteria/config.yaml`.
  - Password: `weeb-secure-password-2026`.

### 2.3 Layer 3 Tunnel Drivers (AmneziaWG 3.0 & 2.0)
- **AmneziaWG 3.0 (`awg3` docker container):**
  - Image: `vaiprog/amnezia-wg-3:latest`.
  - Port: `443/udp`. Subnet: `10.8.3.0/24` (GW `10.8.3.1`).
  - Volume config: `/etc/amnezia-awg3/awg/awg0.conf`.
- **AmneziaWG 2.0 (`amnezia-awg2` docker container):**
  - Image: `vaiprog/amnezia-wg-3:latest` (running amneziawg-go v3/v2 userspace).
  - Port: `51820/udp`. Subnet: `10.8.2.0/24` (GW `10.8.2.1`).
  - Volume config: `/etc/amnezia-awg2/awg/awg0.conf`.

---

## 3. File System Layout & BalanSir-Ready Structure

On the VPS (`199.68.199.68`):
```text
/etc/balansir/
  ├── node.toml                 # Node metadata (ram=961MB, arch=x86_64)
  └── drivers/
      ├── xray-server.toml
      ├── awg3.toml
      ├── awg2.toml
      ├── hysteria.toml
      └── adguardhome.toml
/run/balansir/                  # Secrets (mode 0600 per ADR-006)
/var/lib/balansir/              # Durable runtime state
```

In the local BalanSir repo (`/Users/egorich/ai-workstation/Projects/BalanSir`):
- **Server Profile:** `config/profiles/fornex-weeb.toml`
- **Provisioned Client Artifacts:** `~/Documents/vpn-node-weeb/keys.md` (contains all 5 protocols for 20 devices).

---

## 4. Next Steps for BalanSir Integration Agent

1. **Implement Concrete Drivers in `balansir-daemon`:**
   - Map `XrayServerDriver` to manage `/usr/local/etc/xray/config.json` and `systemctl restart xray`.
   - Map `AmneziaWGUserspaceDriver` to manage docker containers (`awg3`, `amnezia-awg2`) via Docker API or CLI.
   - Map `AdGuardHomeDriver` to manage AdGuardHome configuration and service lifecycle.
2. **State & Health Integration:**
   - Implement health checks (`health_check(&self) -> HealthStatus`) checking port listeners (`ss`) and container health (`docker inspect`).
3. **Secrets Management:**
   - Enforce ADR-006 path conventions (`/run/balansir/<driver>-<id>.json`, `0600` permissions, zeroize on drop).
