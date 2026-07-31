# BalanSir

Network Policy Engine для embedded Linuxустройств.

## Overview

BalanSir — оркестратор сетевых сервисов (VPN, прокси, DPI bypass) для Linux роутеров и шлюзов.

### Key Features

- **Policy Engine** — декларативные правила маршрутизации
- **Component Drivers** — управление WireGuard, Xray, Hysteria, B4
- **Health Engine** — circuit breaker с bounded retry
- **Hardware Profiles** — Milk-V Duo S, Raspberry Pi, x86
- **Privilege Separation** — daemon (unprivileged) + executor (privileged)
- **Binary IPC** — postcard-based протокол

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    balansir-daemon                      │
│              (unprivileged, RSS ≤ 12MB)                │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │   API    │  │  Policy  │  │  State   │             │
│  │  (axum)  │  │  Engine  │  │  Store   │             │
│  └──────────┘  └──────────┘  └──────────┘             │
│                       │                                 │
│                  Binary IPC                             │
│                       │                                 │
├───────────────────────┼─────────────────────────────────┤
│                       ▼                                 │
│  ┌──────────────────────────────────────────────────┐  │
│  │              balansir-executor                   │  │
│  │         (privileged, RSS ≤ 8MB)                 │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐     │  │
│  │  │ Network  │  │ Resource │  │ Process  │     │  │
│  │  │ Backend  │  │ Allocator│  │ Manager  │     │  │
│  │  └──────────┘  └──────────┘  └──────────┘     │  │
│  └──────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│                    Linux Kernel                         │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │
│  │ nftables│ │   tc    │ │ netlink │ │WireGuard│     │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘     │
└─────────────────────────────────────────────────────────┘
```

## Supported Protocols

| Protocol | Status | Notes |
|----------|--------|-------|
| WireGuard | Core | VPN туннели |
| VLESS/Xray | Core | Прокси с маскировкой |
| Hysteria 2 | Core | UDP-based обход |
| B4 | Core | DPI bypass |
| AmneziaWG | Optional | Обфусцированный WG |

## Quick Start

```bash
# Build
cargo build --release

# Run daemon (unprivileged)
./target/release/balansir-daemon

# Run executor (privileged)
sudo ./target/release/balansir-executor
```

## Documentation

- [Architecture](docs/adr/)
- [Hardware Profiles](config/profiles/)

## License

MIT OR Apache-2.0
