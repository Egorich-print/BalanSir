# BalanSir Deployment Research — Buildroot / OpenWRT / Vivanta (Gate Step 5)

Status: research (no code changed) · Date: after A1–A4 gate · Purpose: answer
"how would someone actually deploy this on an embedded router / in Vivanta",
and turn the DEFERRED items from the Production Readiness Gate into concrete,
actionable integration plans.

This is a decision-support document, not a commitment to any option. Each
section ends with a recommendation and open questions for the product owner.

---

## 0. What BalanSir ships today (verified)

Three binaries and a TOML config:

- `balansir-daemon` — unprivileged control plane (reconcile, policy, IPC
  control socket, CLI server). Default features: wireguard, xray, hysteria, b4.
- `balansir-cli` — operator tool (status / plan / explain / desired / actual /
  reload) speaking to `daemon.sock`.
- `balansir-executor` — privileged mechanism (root, `CAP_NET_ADMIN`), shells
  to `nft`, owns the `inet` table, IPC command channel over `executor.sock`.

Release profile is embedded-oriented: `opt-level = "z"`, `lto = true`,
`panic = "abort"`, `strip = true`. `tokio::current_thread` is used (embedded
story from the gate). Cross-target CI builds: x86_64/aarch64/riscv64gc-musl;
`.cargo/config.toml` carries cross linkers. systemd units already exist under
`deploy/systemd/` (daemon, executor with capability hardening, IPC socket).

The daemon has a **hardcoded systemd dependency for the privileged side**:
`balansir.socket` provides `daemon.sock` and the executor unit runs as root
with `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`. On OpenWrt (procd) and
Buildroot (busybox init or systemd) the init model differs and this must be
mapped, not assumed.

---

## 1. Buildroot

### Fit

Buildroot is the closest match to the existing cross-target story. It can
produce a bare-metal image for Milk-V Duo S / RPi / x86 from the same
`riscv64gc-musl`/`aarch64-gnu` targets the CI already builds.

### Integration shape

Two idiomatic Buildroot packages:

1. `package/balansir/balansir.mk` — cargo package that:
   - builds the three binaries with the target's toolchain (Rust cross via
     BR2_TOOLCHAIN or the host rustc with the right target);
   - installs them to `/usr/bin`;
   - installs `config/balansir.toml` + profiles to `/etc/balansir/`;
   - installs the two `.service` units and the `.socket` unit to the target
     init system (systemd when BR2_INIT_SYSTEMD, else a procd-style init).
2. `Config.in` — depends on `BR2_PACKAGE_NFTABLES` (executor shells to `nft`),
   `BR2_TOOLCHAIN_HAS_THREADS`, and a target with netlink support.

### What must change in this repo

- A `--no-default-features` build for the daemon (drop wireguard/xray/hysteria
  until the drivers are wired; A3 made policy real, the drivers are still
  mostly stubs). The gate already treats driver orchestration as future work.
- An init-script abstraction: today systemd units are the only artifact.
  Buildroot with busybox init needs a start-stop script or procd. Recommend:
  keep systemd units as canonical, add a thin `deploy/procd/` set only when a
  real OpenWrt target appears (Section 2).
- Decide the runtime user: the daemon unit runs as `User=balansir`. Buildroot
  must create this user via `users-table.txt` (or run both as root, which the
  gate's product decision on the UID model must settle — see Section 4).

### Recommendation

Treat Buildroot as the **primary embedded packaging path** (it matches the
cross-target CI and the Milk-V Duo S target in the README). Effort is one
`.mk` + `Config.in` + a users-table entry; no daemon code changes expected
beyond feature-gating the stub drivers. **Open question for product**: is
Buildroot a supported integration or only a demonstration target?

---

## 2. OpenWrt

### Fit

OpenWrt is the likely *real* deployment environment (router/gateway appliance)
but it is also the most opinionated: procd init, opkg packaging, its own
nftables/ubus environment, and a strong convention that system services are
lightweight and Lua/shell-friendly. OpenWrt kernels and musl are close to what
BalanSir targets.

### Integration shape

An OpenWrt package `net/balansir/Makefile`:

- `PKG_BUILD_DEPENDS` on a rust toolchain (OpenWrt has `cargo` in the SDK).
- Compiles with `--target <arch>-openwrt-linux-musl` against the SDK's
  toolchain; installs to `/usr/bin`.
- `init.d/balansir-daemon` + `init.d/balansir-executor` procd scripts:
  - `procd_set_param command /usr/bin/balansir-daemon`
  - `procd_set_param respawn`
  - executor script runs with `procd_set_param capabilities` and the
    `net_admin` capability (procd supports `procd_set_param capabilities`).
  - socket dir `/var/run/balansir` created by procd `procd_set_param` +
    `mkdir` in start_instance.
- `/etc/config/balansir` — UCI config file that maps onto the daemon's TOML
  (either by generating the TOML from UCI on start, or by pointing the daemon
  at `/etc/config/balansir`). Recommend the former (generate TOML) to keep the
  daemon's strict parser as the single source of truth.
- Depends on `nftables`.

### The hard part

- **IPC sockets live in /run**: procd must create `/run/balansir` with the
  right owner before either service starts.
- **Capability model**: OpenWrt's default `procd` can grant `net_admin`; the
  systemd `AmbientCapabilities` approach does not translate 1:1, and the
  executor currently binds to a fixed path `/run/balansir/executor.sock` that
  assumes a writable state dir.
- **nft availability**: some OpenWrt builds ship `nft` but BalanSir shells to
  it; the package must hard-depend on it and be explicit about the `inet`
  table name not colliding with OpenWrt's own firewall table.

### Recommendation

Defer a full OpenWrt package until there is a concrete appliance target and a
UCI mapping decision. The **research outcome** is that OpenWrt is feasible
without daemon changes **if** two small config hooks land first:
(1) socket/config paths configurable via env/CLI (today they are
`/run/balansir/*` constants in `main.rs`/`cli.rs`/`secrets.rs`), (2) a
`BALANSIR_NFT_BIN` override in the executor (today `nft` is resolved from the
standard system dirs + `$PATH` via `resolve_bin` — `which`-based, already
mechanism-safe, but not overridable, which matters for non-default OpenWrt
layouts). **Open question for product**: which OpenWrt target (x86_64 router?
MIPS?) and whether UCI or plain TOML is the operator-facing config.

---

## 3. Vivanta

### Context

Vivanta is a separate OS/kernel project (AArch64, memory management). The gate
lists "any Vivanta embedding" as research, and the ADR trail notes
"Buildroot/OpenWRT/Vivanta" together. This section is therefore about how
BalanSir would run *on* or *inside* Vivanta, not about changing Vivanta.

### What embedding means

Two distinct levels:

1. **User-space on a Vivanta-based image**: Vivanta provides the OS; BalanSir
   is a normal root service. This is just another init/packaging story
   (Section 1/2 pattern) — no kernel coupling needed, because BalanSir
   enforces via **nftables in the kernel**, not via a custom datapath.
2. **Kernel-level enforcement**: BalanSir's executor talks to the kernel's
   netfilter/nft subsystem. On Vivanta this requires that Vivanta's kernel
   exposes a compatible netfilter interface. If Vivanta is not a Linux kernel,
   the whole executor mechanism must be re-plumbed (netlink → Vivanta's own
   packet API) — a major project, not an integration detail.

### Research finding

BalanSir is deliberately **mechanism-agnostic on the data plane**: the
daemon compiles policy, the executor is a thin adapter to a mechanism, and the
A1/A2/A3 work kept identity/inventory in the executor contract (`Executor`
trait + `GetActualRules` IPC). A Vivanta port would therefore mean writing a
new `Executor` implementation (a Vivanta mechanism adapter) plus a new IPC
transport if the control sockets cannot be Unix sockets. The daemon, planner,
config, and CLI would carry over unchanged.

### Recommendation

Treat Vivanta as a **future mechanism port**, not a packaging target. The
concrete prerequisite is a documented `Executor`/mechanism contract (the trait
exists; ADR-015/016/018 make identity and inventory part of it). **Open
question for product**: is there a real Vivanta-on-BalanSir timeline, or is
Vivanta embedding aspirational (in which case this stays a research note)?

---

## 4. Cross-cutting: the product decisions this research exposes

The gate's product-semantics items are forced by every packaging path above:

1. **Runtime UID model** — systemd runs the daemon as `balansir` and the
   executor as root with capabilities. Buildroot must create the user; OpenWrt
   procd grants capabilities differently. The default allowlist `[0]`
   (`BALANSIR_ALLOWED_UIDS`) means an operator on a plain router must be root
   to run the CLI. **Decision needed**: a dedicated `balansir` operator group
   and a `BALANSIR_ALLOWED_UIDS` example in every packaged config.
2. **Fail-open vs fail-closed** — an empty config installs nothing (current,
   honest behavior). On an embedded appliance "nothing installed" usually
   means the box passes everything. Packaging must state this explicitly per
   profile; it is a product choice, not an engineering one.
3. **Config source** — TOML file today. UCI (OpenWrt) or Buildroot config
   fragments are wrappers, not a second truth. Recommended: the TOML stays
   authoritative; UCI only renders TOML.

---

## 5. Recommendation summary

| Path | Effort | Gate risk | Recommendation |
|---|---|---|---|
| Buildroot package | small (.mk + Config.in + users-table) | none | Do first — matches cross-target CI |
| OpenWrt package | medium (procd, UCI, capability mapping) | none | Defer to a real appliance target |
| Vivanta embedding | large if kernel-level (new mechanism) | high | Research note only; daemon is portable |

**No code was changed by this document.** The two small config hooks that would
de-risk OpenWrt (configurable socket paths, `BALANSIR_NFT_BIN` already
resolved) are listed in Section 2 and can be implemented as a separate
decision.
