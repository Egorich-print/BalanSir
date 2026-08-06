<p align="center">
  <img src="docs/logo.svg" alt="BalanSir" width="200">
</p>

<h1 align="center">BalanSir</h1>

<p align="center">
  <a href="README.ru.md">Русский</a>
</p>

<p align="center">
  <strong>Network Policy Engine for Linux Routers and Gateways</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#building">Building</a> •
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20RISC--V%20%7C%20ARM64%20%7C%20x86__64-green?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/status-alpha-yellow?style=flat-square" alt="Status">
</p>

---

## What is BalanSir?

BalanSir is a **lightweight Network Policy Engine** written in Rust for embedded Linux devices, routers, and gateways. It orchestrates VPN tunnels, proxies, and DPI bypass mechanisms through a unified policy-driven architecture.

**Think of it as a programmable network control plane** — not another VPN client, but the layer that decides *which* traffic goes *where* and *how*.

### Why BalanSir?

| Problem | Solution |
|---------|----------|
| Multiple VPN clients with separate configs | Unified policy engine with declarative rules |
| No visibility into routing decisions | Decision Trace explains every packet path |
| Manual failover between tunnels | Automatic health monitoring with circuit breaker |
| Hard to add new protocols | Trait-based driver SDK — plug in any protocol |
| Resource-constrained devices | Optimized for 512MB RAM, single-core RISC-V |

---

## Features

### Core

- **Policy Engine** — Declarative routing rules with domain, IP, protocol, and latency matchers
- **Decision Trace** — Every routing decision is explainable (like `iptables -v` meets OPA)
- **Privilege Separation** — Unprivileged daemon + privileged executor via binary IPC
- **Hardware Profiles** — Milk-V Duo S, Raspberry Pi, x86, OpenWrt

### Protocols

| Protocol | Status | Use Case |
|----------|--------|----------|
| **WireGuard** | Core | VPN tunnels |
| **VLESS/Xray** | Core | Proxy with traffic obfuscation |
| **Hysteria 2** | Core | UDP-based bypass for unstable networks |
| **B4** | Core | DPI bypass at packet level |
| **AmneziaWG** | Optional | Obfuscated WireGuard |
| **Shadowsocks** | Optional | Legacy proxy support |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Policy Engine                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
│  │   Matcher   │  │  Decision   │  │  Executor   │       │
│  │  (AST-like) │→ │   Trace     │→ │  (kernel)   │       │
│  └─────────────┘  └─────────────┘  └─────────────┘       │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │WireGuard │  │   Xray   │  │ Hysteria │  │    B4    │  │
│  │ Driver   │  │  Driver  │  │  Driver  │  │  Driver  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Linux Kernel (nftables/netlink)         │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Example Policy

```toml
# Route YouTube through Hysteria (fast, UDP-based)
[[rules]]
name = "youtube-hysteria"
priority = 100
enabled = true
matcher = { type = "DomainSuffix", suffix = ".youtube.com" }
action = { type = "Forward", driver = "hysteria" }

# Route Steam through WireGuard (low latency)
[[rules]]
name = "steam-wireguard"
priority = 90
enabled = true
matcher = { type = "DomainSuffix", suffix = ".steamcontent.com" }
action = { type = "Forward", driver = "wireguard" }

# Russian sites go direct
[[rules]]
name = "ru-direct"
priority = 80
enabled = true
matcher = { type = "GeoIp", country = "RU" }
action = { type = "Allow" }

# Block ads
[[rules]]
name = "block-ads"
priority = 200
enabled = true
matcher = { type = "DomainSuffix", suffix = ".doubleclick.net" }
action = { type = "Block" }
```

### Decision Trace Output

```
Packet: 192.168.1.100:54321 → 142.250.80.46:443 (TCP)

Decision: Forward { driver: hysteria }
Reason:   Matched rule: youtube-hysteria
Time:     42µs

Trace:
  ✓ youtube-hysteria (DomainSuffix: ".youtube.com") — matched
  ✗ steam-wireguard (DomainSuffix: ".steamcontent.com") — no match
  ✗ ru-direct (GeoIp: "RU") — no match
```

---

## Quick Start

### Install from source

```bash
# Clone
git clone https://github.com/Egorich-print/BalanSir.git
cd BalanSir

# Build
make build

# Install (requires root)
sudo make install

# Configure
sudo nano /etc/balansir/balansir.toml

# Start
sudo systemctl start balansir-daemon
sudo systemctl start balansir-executor
```

### Docker

```bash
docker run -d \
  --name balansir \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v /etc/balansir:/etc/balansir \
  -p 8080:8080 \
  balansir/balansir:latest
```

### Verify

```bash
# Check status
balansir-cli status

# View decision trace
balansir-cli explain --dst 142.250.80.46:443

# View logs
journalctl -u balansir-daemon -f
```

---

## Configuration

### Hardware Profiles

BalanSir automatically detects hardware and applies appropriate limits:

| Profile | RAM | CPU | Max Drivers | Runtime |
|---------|-----|-----|-------------|---------|
| `milkv-duos` | 512MB | 1 core | 1 | `current_thread` |
| `rpi4` | 1-8GB | 4 cores | 3 | `multi_thread` |
| `x86` | 4GB+ | 4+ cores | 5 | `multi_thread` |

### Main Config (`/etc/balansir/balansir.toml`)

```toml
[general]
hostname = "gateway"
log_level = "info"

[network]
wan = ["eth0"]
lan = ["br-lan"]
dns = ["1.1.1.1", "8.8.8.8"]

[api]
enabled = true
bind = "127.0.0.1:8080"

[health]
check_interval_sec = 30
failure_threshold = 3
```

---

## Building

### Prerequisites

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# For cross-compilation to RISC-V
rustup target add riscv64gc-unknown-linux-musl
```

### Build Commands

```bash
# Debug build
make dev

# Release build
make build

# Run tests
make test

# Cross-compile for RISC-V
make build RISCV=1

# Install system-wide
sudo make install

# Uninstall
sudo make uninstall
```

---

## Documentation

### Architecture Decision Records

- [ADR-000: Project Philosophy](docs/adr/ADR-000-philosophy.md)
- [ADR-001: State Store](docs/adr/ADR-001-state-store.md)
- [ADR-002: Driver Model](docs/adr/ADR-002-driver-model.md)
- [ADR-005: Privilege Separation](docs/adr/ADR-005-privilege-separation.md)

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Policy Engine** | Evaluates rules and produces Decision Traces |
| **Driver** | Manages lifecycle of a network service (WireGuard, Xray, etc.) |
| **Executor** | Privileged process that applies actions to kernel |
| **Decision Trace** | Explains why a packet was routed a specific way |
| **Circuit Breaker** | Health recovery with bounded retries |
| **Hardware Profile** | Device-specific configuration and limits |

---

## Project Status

**Current Phase: Phase 3 (Complete)**

- [x] Policy Engine with AST-like matchers
- [x] Decision Trace for every packet
- [x] Binary IPC with correlation IDs
- [x] WireGuard driver
- [x] Xray driver skeleton
- [x] Network namespace integration tests
- [x] Hardware profiles (Milk-V Duo S, RPi4, x86)

**Next: Phase 4 — Reconciliation Loop**

---

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) first.

### Development Setup

```bash
git clone https://github.com/Egorich-print/BalanSir.git
cd BalanSir
make dev
make test
```

### Running Tests

```bash
# All tests
make test

# With verbose output
cargo test -- --nocapture

# Integration tests (requires root)
sudo cargo test -p balansir-tests -- --ignored
```

---

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

---

## Acknowledgments

- [WireGuard](https://www.wireguard.com/) — Fast, modern VPN
- [Xray-core](https://github.com/XTLS/Xray-core) — VLESS protocol
- [Hysteria](https://github.com/apernet/hysteria) — UDP-based proxy
- [B4](https://github.com/DanielLavrushin/b4) — DPI bypass
- [LibreQoS](https://github.com/LibreQoE/LibreQoS) — Traffic management inspiration

---

<p align="center">
  Made with ❤️ for the Russian internet freedom community
</p>
