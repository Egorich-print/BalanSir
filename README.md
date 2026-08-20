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
  <a href="#what-is-balansir">What is BalanSir</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#components">Components</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#building">Building</a> •
  <a href="#testing">Testing</a> •
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux-green?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/status-alpha-yellow?style=flat-square" alt="Status">
</p>

---

## What is BalanSir?

BalanSir is a **network policy engine** written in Rust for Linux routers, gateways,
and embedded devices. It applies declarative rules to traffic, manages VPN and proxy
transport drivers, and exposes a unified control-plane API and WebUI.

It is **not** a VPN client. It is the layer that decides *which* traffic goes *where*
and *how*, then drives the transports and kernel state (nftables/netlink) through a
privilege-separated daemon/executor pair.

> Status: **alpha**. The project is under active development; the codebase and this
> README describe the current `main` branch. Some components are implemented more
> deeply than others — see the per-component status below.

### Why BalanSir?

| Problem | What BalanSir does today |
|---------|--------------------------|
| Multiple VPN/proxy configs | Unified transport layer with per-protocol drivers |
| VPN profile selection | `VpnPool` weighted selection with per-profile health probing |
| Local runtime death | L2 lifecycle watchdog (ADR-033): bounded restart/recovery guard |
| No visibility into routing | Decision traces, `/subsystems` snapshot, Prometheus metrics |
| Privilege separation | Unprivileged daemon + root executor over authenticated IPC |

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     balansir-daemon (unprivileged)             │
│                                                                │
│  PolicyEngine (compiles rules → ActionRequest)  VpnPool (L1)   │
│       │                                            │           │
│       ▼                                            ▼           │
│  Coordinator/Reconciler ──── XrayManager ──── B4/DPI engine    │
│       │                           │              │             │
│  IPC (postcard + SO_PEERCRED)     │              │             │
└───────┼───────────────────────────┼──────────────┼─────────────┘
        ▼                           ▼              ▼
┌────────────────────────────────────────────────────────────────┐
│               balansir-executor (root, minimal)                │
│     nftables / ip-rule / netlink / interface / QoS / path-MTU  │
└────────────────────────────────────────────────────────────────┘
```

The project follows the **Policy → Mechanism** split: drivers and the executor apply
mechanism (nftables, kernel state, processes); the policy engine and control plane make
decisions. Two processes communicate over an authenticated binary IPC protocol
(postcard framing + `SO_PEERCRED` peer validation, ADR-005/ADR-004/ADR-011).

## Components

### Policy Engine

A declarative rule engine. Desired-state rules (`config/balansir.toml`, `[[rules]]`)
are compiled into backend-neutral `ActionRequest`s and applied through the executor
(nftables/netlink) by the reconciliation loop. A standalone matcher-based `PolicyEngine`
(domain/IP/port/protocol matchers) with decision traces also exists and is used by the
stress tests; it is not yet wired into the daemon's runtime policy path.

- Config rule actions (parsed from `[[rules]]`): `allow`, `block`, `reject`, `log`.
  The broader `Action` enum (route/mark/forward/shape/queue) exists at the executor
  boundary but is not yet reachable from the TOML config.
- Health-driven rule fallback (`rule.fallback`) is implemented in the standalone
  engine only, not yet exposed from the TOML config.
- There is **no** GeoIP or latency matcher yet.

### VPN

VPN profile management lives in `balansir-vpn` plus the daemon's `vpn_manager.rs`:

- **Profile probe** → **TCP connect probe** → **PathSample** → **PathHealth** → **VpnPool**.
- `TcpConnectProbe` is a bounded TCP-connect reachability check of `server:port`
  (IPv6-safe). Its result feeds `PathHealth` (EMA latency, hysteresis, anti-flap
  cooldown) — the **L1** health signal.
- `VpnPool` performs weighted profile selection (health weight + availability bonus −
  latency/load penalties), enforces a minimum dwell time (default 120 s), and cycles
  profiles through `Healthy → Degraded → Failed → Cooldown → Recovering → Healthy`
  states. When no eligible profile remains, the active profile is cleared (traffic
  stays direct).
- The selected profile is handed to `XrayManager` via a pool consumer
  (`apply_pool_profile`); the pool is authoritative for selection.
- **Geo-spoofing (split tunnel)**: the Xray component config
  (`BALANSIR_XRAY_CONFIG`) accepts a `geo_domains` list. When set, only
  traffic to those domains is routed through the active VPN outbound; all
  other traffic goes direct. This gives per-service geo-spoofing (e.g.
  Spotify, Gemini) without proxying the whole LAN. Empty list = all proxied
  traffic goes through the VPN (legacy behavior). Example:

  ```toml
  socks_port = 10808
  http_port = 10809
  geo_domains = ["spotify.com", "api.spotify.com", "gemini.google.com"]
  ```

**Supported subscription formats** (`balansir-vpn` importer): `vless://` URIs
with `type=tcp|ws|grpc|httpupgrade|xhttp` and
`security=none|tls|reality` (`security=false` is accepted as a `none` alias;
for WS/HTTPUpgrade/XHTTP TLS configs without `sni=` the effective SNI is
derived from the `host=` fronting domain, and the Host header is preserved
end-to-end). xhttp (splithttp) is fully supported (mission §10): `mode` and
optional `extra` JSON are passed through to the generated runtime config.
Everything else is rejected with an explicit reason — never silently
imported: `hysteria2://`, `trojan://`, `vmess://`, `ss://`.

### Xray / L2 health

`XrayManager` runs the active Xray driver (VLESS/Reality), supervises it with
`driver.health_check()`, and manages per-endpoint `PathHealth` failover for static
endpoints. For the pool-driven runtime it owns the **L2 watchdog** (ADR-033).

**Health model (ADR-033)**:

- **L1** — remote TCP reachability of `server:port`. Per-profile. Selection-relevant.
- **L2** — local active-driver liveness (`kill(pid,0)` + local SOCKS inbound accept).
  Lifecycle-relevant.
- **L3** — real tunneled request. Not implemented.

**L2 watchdog (implemented)** — a bounded restart/recovery guard owned by
`XrayManager` for the *pool-driven* active runtime. It is deliberately separate
from the L1 pool health model and never influences profile ranking/selection:

- A startup **grace window** (default 10 s) tolerates non-Healthy results while
  the driver is coming up; after it closes, non-Healthy is treated as evidence.
- On failure outside grace it restarts the **same** driver (never switches VPN
  profile), respecting a **backoff** gap (default 5 s).
- Restarts are bounded: **max_restarts** (default 3) within a rolling
  **window_ms** (default 60 s). When the budget is spent the runtime is
  **exhausted and stopped** (traffic direct) — no infinite restart loop. A
  fresh start grants a new bounded budget.
- Verified by unit tests covering grace, evidence, bounded budget exhaustion,
  backoff gaps, same-driver restart, exhaustion-stops-runtime, and
  non-rotation of candidates.

### B4 / DPI

- **B4** (`balansir-b4` + daemon `b4_engine`): pure-Rust NFQUEUE engine
  (netlink-sys, no libnetfilter-queue dependency) with flow classification,
  packet-level strategies (MSS/StripSack/TTL), and a catch-all profile fallback.
  It is a policy-controlled *adaptation* layer (decides *how* to deliver a flow),
  never a policy authority. Enabled via `BALANSIR_B4_CONFIG`.
- **DPI manager** (`b4_dpi.rs`): installs/removes nftables queue rules via the
  executor, detects a dead engine, and returns to the direct path on stop
  (never blackholes). Enabled via `BALANSIR_DPI_CONFIG`.

### Drivers

| Driver | Status | Notes |
|--------|--------|-------|
| **Xray** (VLESS/Reality) | Implemented | Real driver; SOCKS/HTTP inbound, `health_check` (pid + local accept) |
| **B4** | Implemented | NFQUEUE engine + DPI manager |
| **DNS forwarder** | Implemented | SOCKS5 UDP relay, cache, DNS registry |
| **UPnP** | Implemented | SSDP discovery + SOAP port mapping |
| **Hysteria 2** | Implemented | Config + driver present |
| **Tailscale** | Experimental | Free functions orchestrating `tailscale`; not a `ComponentDriver` |
| **WireGuard** | Partial | Interface up/addr, but no `wg setconf` (keys/peers not applied) |
| **AmneziaWG** | Partial | Same as WireGuard; feature-gated |

Enabled by default: `wireguard`, `xray`, `hysteria`, `b4`, `dns` (Cargo feature flags).

### Executor / daemon

- `balansir-daemon`: unprivileged process, `current_thread` tokio runtime, owns the
  policy/reconciliation loop, drivers, VPN pool, DNS, B4/DPI, Xray, API server, and
  the shared subsystem snapshot. Startup config via `BALANSIR_CONFIG` (a malformed
  config is fatal; no config = start empty, ADR-027).
- `balansir-executor`: minimal root process, refuses to start unless `euid == 0`,
  applies nftables/ip-rule/interface/QoS/path-MTU changes, and validates peers over
  IPC (`SO_PEERCRED`, GID `1500`).

### API

Axum HTTP server (`balansir-api`) with REST + SSE:

- Health/readiness: `/health`, `/ready`, `/live`, `/version`, `/build-info`
- State: `/desired`, `/actual`, `/state`, `/drift`, `/subsystems`, `/system`
- Control: `/reconcile`, `/reload`, `/drivers`, `/drivers/:id/restart`
- VPN: `/vpn/pool`, `/vpn/pause`, `/vpn/refresh`, `/vpn/rotate`, `/vpn/pin`
- Xray: `/xray`, `/xray/pause`, `/xray/select`, `/xray/rotate`
- B4/DPI: `/b4`, `/b4/pause`, `/dpi`
- Path: `/path/decision`; QoS: `/qos`; Interfaces: `/interfaces`
- Events: `/events/stream` (SSE); Metrics: `/metrics` (Prometheus)

### OTA

`balansir-ota` provides A/B slot updates (mmcblk0p2/p3, `cmdline.txt` boot swap),
Ed25519-signed manifests with key rotation, boot-confirmation and rollback.
`tools/balansir-image` builds/inspects/verifies firmware images.

### WebUI

A Svelte dashboard (`webui/`) that renders the same `PathHealth`/subsystem state the
managers use — the UI can never disagree with the runtime decisions.

---

## Quick Start

### Build from source

```bash
git clone https://github.com/Egorich-print/BalanSir.git
cd BalanSir

# Release build
make build

# Run tests
make test

# Development (debug) build
make dev
```

### Install (Linux, requires root)

```bash
sudo make install
```

Installs `balansir-daemon`, `balansir-executor`, and `balansir-cli`, plus example
config and systemd units.

```bash
# Configure
sudo nano /etc/balansir/balansir.toml

# Start
sudo systemctl start balansir-executor
sudo systemctl start balansir-daemon
```

### Verify

```bash
# CLI (requires a running daemon socket)
balansir-cli status
balansir-cli explain

# REST API
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/subsystems
```

> `balansir-cli` commands: `status`, `plan`, `explain`, `desired`, `actual`,
> `fingerprint`, `reload <config.toml>`.

### Docker

A multi-stage `Dockerfile` and `docker-compose.yml` are provided. The image is built
from this repository (it is not published to a public registry):

```bash
docker compose up -d
```

---

## Configuration

BalanSir is configured via environment variables and TOML files. The daemon loads a
desired-state policy from `BALANSIR_CONFIG` (example: `config/balansir.toml`); the
other components are enabled by their own variables (`BALANSIR_B4_CONFIG`,
`BALANSIR_DPI_CONFIG`, `BALANSIR_XRAY_CONFIG`, `BALANSIR_VPN_CONFIG`,
`BALANSIR_DNS_CONFIG`). The API server binds per `BALANSIR_API_BIND`.

### Policy rules (`BALANSIR_CONFIG`)

```toml
[policy]
# "pass" (fail-open, default) or "drop" (fail-closed: single terminal drop)
empty_config_action = "pass"

[[rules]]
id = 1
action = "block"
priority = 100

# Flow-level matchers are optional (src/dst IP, dst port, protocol, domain):
# [[rules]]
# id = 2
# action = "allow"
# priority = 90
# dst_domain = "example.com"
# dst_port = 443
# protocol = "tcp"

[[drivers]]
id = "dns"
action = "start"
```

### Hardware profiles

Device profiles live in `config/profiles/` (`milkv-duos`, `x86`, `fornex-weeb`). They
select runtime flavor, memory limits, enabled drivers, firewall budgets, and OTA slot
policy. A Raspberry Pi 3B buildroot image is generated from
`buildroot-external/configs/balansir_rpi3b_64_defconfig`.

---

## Building

### Prerequisites

- Rust toolchain (stable)
- For cross-compilation, the relevant cross C toolchain (see
  `.cargo/config.toml`; linkers are configured per target)

### Commands

```bash
make dev       # debug build
make build     # release build
make test      # run tests
make check     # cargo check + clippy
make install   # system-wide install (Linux)
make uninstall
```

### Cross-compilation targets

CI cross-builds `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, and
`riscv64gc-unknown-linux-musl`. These are **build/CI targets** — they do not imply
hardware testing. Only the Raspberry Pi 3B (buildroot image + gateway E2E harness)
has been exercised on real hardware.

---

## Testing

```bash
cargo test --workspace --no-fail-fast
```

Current `main` baseline: **483 tests passing, 0 failing, 4 ignored** (root-gated
netns tests). Run the root-gated netns tests with:

```bash
sudo cargo test -p balansir-tests -- --ignored
```

Test surface includes unit tests, the gateway E2E harness (`tests/gateway_e2e.sh`,
run on the Pi), IPC integration tests, and stress tests.

---

## Documentation

- [Architecture audit](ARCHITECTURE_AUDIT.md)
- [Technical debt](TECH_DEBT.md)
- [Roadmap](ROADMAP.md)
- [Project state](PROJECT_STATE.md)
- [Operation status](STATUS.md)
- [Architecture Decision Records](docs/adr/) — ADR-000 … ADR-033
  (notable: [ADR-005 privilege separation](docs/adr/ADR-005-privilege-separation.md),
  [ADR-027 startup config](docs/adr/ADR-027-startup-config-recovery.md),
  [ADR-033 two-level health model](docs/adr/ADR-033-two-level-health-model.md))

---

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.