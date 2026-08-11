# ADR-029: Raspberry Pi 3B+ deployment image (aarch64 static)

## Status
Accepted

## Context

The roadmap targets a **REAL LINUX HARDWARE GATE** before the Architecture
Gate. The Raspberry Pi 3B+ (BCM2837B0, AArch64, usually Raspberry Pi OS /
Debian arm64) is a concrete, cheap target. BalanSir's cross-target CI already
builds aarch64; what was missing was a reproducible way to produce runnable
binaries and a deploy path onto the device.

The existing `.cargo/config.toml` had a link to `aarch64-linux-gnu-gcc` for the
glibc target, but that toolchain is not installed on the build host, and a
glibc binary would also depend on the target's libc version. A **static musl**
build is the right artifact: no libc dependency on the target at all.

## Decision

Produce **statically linked aarch64 musl binaries** for the three executables
and a deploy package:

- **Target:** `aarch64-unknown-linux-musl`.
- **Linker:** `zig` used as a GNU-style linker via a `zig-cc` shim
  (`exec zig cc -target aarch64-linux-musl "$@"`).
- **CRT/libc:** `-C link-self-contained=no` so zig supplies musl libc/CRT and
  Rust does not also add its self-contained CRT objects — this is what avoids
  the duplicate-`crt1.o`/`_start_c` link failure seen on Apple's `ld` and on
  zig's auto-crt injection.
- **Config:** the linker + rustflags are recorded in `.cargo/config.toml`
  (`[target.aarch64-unknown-linux-musl]`) so the build is reproducible.
- **Package:** `deploy/rpi3b/`
  - `build-aarch64.sh` — builds all three binaries.
  - `install.sh` — SSH deploy: copy binaries to `/usr/local/bin`, install
    systemd units (`balansir-daemon` with `BALANSIR_CONFIG`,
    `balansir-executor` with `CAP_NET_ADMIN`/`CAP_NET_RAW`), write a starter
    `/etc/balansir/balansir.toml` (only if absent), enable + start.
  - `README.md` — build, deploy, verify, behaviour notes.

Artifacts are small static ELF aarch64 binaries (~0.6–1.2 MB):
`balansir-daemon` 1.2 MB, `balansir-executor` 892 KB, `balansir-cli` 567 KB.

## Consequences

- The Pi 3B+ gets dependency-free binaries: no glibc/nss on the target, works
  on Raspberry Pi OS / Debian arm64 / any aarch64 Linux.
- Startup config recovery (P7.2.1) is wired into the installed daemon unit via
  `BALANSIR_CONFIG`, so the box restores its last accepted desired state after
  reboot without an operator.
- `balansir-cli` runs on the Pi for status/fingerprint/reload; the operator
  does not need a second machine.
- A full Buildroot SD image remains an alternative (documented in the README
  and `DEPLOYMENT_RESEARCH.md` §1) but is not required for the hardware gate.
- The `zig-cc` shim must exist on PATH; `build-aarch64.sh` fails loudly if it
  does not. This is documented.

## Verification

- `file` on all three artifacts: `ELF 64-bit LSB executable, ARM aarch64,
  version 1 (SYSV), statically linked, stripped`.
- `cargo check` passes for `aarch64-unknown-linux-musl`, `x86_64-unknown-linux-gnu`
  and `aarch64-unknown-linux-gnu`; host workspace still 18 suites, clippy 0,
  fmt clean.
- `sh -n` validates both deploy scripts.

## Relation to other gates

- Provides the artifact for the **REAL LINUX HARDWARE GATE** (P7.3 privileged
  MTU + netns proof run on the Pi).
- Composes with P7.2.1 (startup config), P7.2.2 (shared DNS registry),
  ADR-020 (ownership loop) — the installed daemon carries all of them.
