# BalanSir on Raspberry Pi 3B+ (arm64)

Deploy BalanSir as a static, dependency-free network policy engine on a
Raspberry Pi 3B+ running Raspberry Pi OS / Debian **arm64**.

## Why this works on the 3B+

- The 3B+ is **AArch64** (BCM2837B0). We cross-compile for
  `aarch64-unknown-linux-musl` → **statically linked ELF** binaries with no
  glibc/nss dependency, so they run on any 64-bit Linux regardless of libc
  version.
- BalanSir's privileged executor only needs `nft` + `CAP_NET_ADMIN`; the
  systemd units grant exactly that.

## Build (on macOS or any Rust host)

```sh
# one-time tooling
rustup target add aarch64-unknown-linux-musl
brew install zig
printf '#!/bin/sh\nexec zig cc -target aarch64-linux-musl "$@"\n' > /usr/local/bin/zig-cc
chmod +x /usr/local/bin/zig-cc

# build
./deploy/rpi3b/build-aarch64.sh
```

Artifacts (statically linked, ~0.6–1.2 MB each):

```
target/aarch64-unknown-linux-musl/release/balansir-daemon
target/aarch64-unknown-linux-musl/release/balansir-executor
target/aarch64-unknown-linux-musl/release/balansir-cli
```

> The build uses `zig` only as the linker (`-C link-self-contained=no`), so
> zig supplies musl libc/CRT and Rust does not duplicate them. This avoids the
> duplicate-crt link failure on Apple's `ld`.

## Deploy

```sh
./deploy/rpi3b/install.sh pi@<pi-ip>
```

This copies the binaries to `/usr/local/bin`, installs systemd units
(`balansir-daemon`, `balansir-executor`), writes a starter
`/etc/balansir/balansir.toml` (only if absent), and enables/starts both
services.

## Verify on the Pi

```sh
systemctl status balansir-daemon balansir-executor
balansir-cli status                 # health + plan + actual
balansir-cli fingerprint            # fingerprint of the loaded config
balansir-cli reload /etc/balansir/balansir.toml   # runtime reload
```

## Behaviour notes

- **Startup config recovery (P7.2.1/ADR-027):** the daemon loads
  `BALANSIR_CONFIG=/etc/balansir/balansir.toml` at boot, **before the first
  reconcile**, so a reboot restores the last accepted desired state without an
  operator reload. A malformed config is a fatal startup error (never silently
  empty).
- **Empty-config semantics (P1/ADR-019):** the starter config sets
  `empty_config_action = "pass"`. For fail-closed behaviour on an appliance,
  change it to `"drop"` (installs a terminal drop).
- **Orphan/ownership loop (P4.1/ADR-020):** the daemon periodically re-seeds
  actual state from the executor's kernel inventory, so external `nft` edits
  and executor restarts are converged back to desired.
- The executor runs as root with only `CAP_NET_ADMIN CAP_NET_RAW`; the daemon
  runs unprivileged.

## Alternative: Buildroot full image

For a fully self-contained SD image (no Raspberry Pi OS), see
`docs/DEPLOYMENT_RESEARCH.md` §1 — Buildroot packaging is the primary embedded
path but is a longer build; this package targets the common Raspberry Pi OS
setup first.
