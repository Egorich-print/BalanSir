# BalanSir on Raspberry Pi 3B+ — Buildroot image

Status: **image built and verified (Buildroot, QEMU-virt pending)** ·
Acceptance labels below.

## Artifacts (Buildroot 2026.05.1, output/images)

| File | Size | Note |
|---|---|---|
| `sdcard.img` | 320 MiB | bootable SD image (MBR: boot.vfat 64M + rootfs.ext4 256M) |
| `Image` | 23 MiB | ARM64 kernel (rpi custom, bcm2711 defconfig) |
| `bcm2710-rpi-3-b-plus.dtb` | 35K | device tree (3B/3B+/CM3) |
| `rootfs.ext4` | 256 MiB | ext4 rootfs (systemd, nftables, iproute2, openssh, balansir) |

Build metadata: Buildroot 2026.05.1 · Linux 6.18-ish rpi tree (commit
21b4101) · Bootlin aarch64 glibc toolchain · host-rustc 1.96.1 ·
`balansir_rpi3b_64_defconfig`.

## Verify the image (on the macOS host)

```sh
cargo run -p balansir-image -- inspect path/to/sdcard.img
cargo run -p balansir-image -- checksum path/to/sdcard.img
cargo run -p balansir-image -- verify path/to/sdcard.img path/to/Image
```

## Flash to the SD card (HUMAN EXECUTION REQUIRED — needs physical access)

```sh
# On Linux (or macOS with the SD device):
# sudo dd if=sdcard.img of=/dev/sdX bs=4M conv=fsync   # ⚠ replaces the disk!
```

On macOS the device is `/dev/diskN`; unmount first (`diskutil unmountDisk`).
**`dd` is destructive — confirm the target device.**

## First boot (factory behavior)

- Networking: DHCP on `eth0`.
- SSH: openssh server; root login — **change the root password / keys on
  first boot** (no password is set by default).
- BalanSir: `balansir-daemon` + `balansir-executor` auto-start (systemd,
  ADR-030 units). `/etc/balansir/balansir.toml` is the factory policy
  (fail-open on empty; operator should `balansir-cli reload` their config).
- Startup recovery (P7.2.1/ADR-027): the daemon loads `BALANSIR_CONFIG` at
  boot, before the first reconcile — a malformed file is a fatal startup
  error, never silently empty.

## Operate

```sh
balansir-cli status          # health + plan + actual
balansir-cli fingerprint     # config fingerprint
balansir-cli reload /etc/balansir/balansir.toml
```

## Acceptance labels

| Item | Status |
|---|---|
| BalanSir cross-build (aarch64 musl static, host) | VERIFIED (ADR-029) |
| Buildroot external tree + RPi defconfig | VERIFIED (image produced) |
| `sdcard.img` MBR/ext4 layout | VERIFIED (`balansir-image inspect` + `file`) |
| Image checksum manifest | VERIFIED (`balansir-image checksum/verify`) |
| QEMU `virt` full-stack boot/network test | PENDING (build in progress) |
| QEMU `raspi3b` boot of sdcard.img | ENVIRONMENT-BLOCKED (no NIC; SD power-of-2 quirk; would need kernel+firmware boot args) |
| Real Raspberry Pi 3B+ | NOT HARDWARE VERIFIED (human step) |

QEMU results are never claimed as hardware verification.
