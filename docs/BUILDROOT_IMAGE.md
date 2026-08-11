# BalanSir Buildroot image for Raspberry Pi 3B+

Status: mission in progress · Acceptance labels: see "Verification" below.

Buildroot is Linux-only. This mission builds the image inside an **aarch64
Ubuntu VM under QEMU on the macOS host** — fully unprivileged (no sudo on the
host, no Docker). The result is a bootable `sdcard.img` for the Raspberry Pi
3B+ (AArch64).

## Architecture

```text
macOS host (Apple silicon, QEMU installed)
   └── QEMU -M virt (aarch64, HVF/TCG)  →  Ubuntu 24.04 arm64 cloud VM
          └── Buildroot 2025.02.16 LTS  →  BR2_EXTERNAL=buildroot-external
                 └── balansir_rpi3b_64_defconfig
                        ├── Linux kernel (rpi custom, bcmrpi3 defconfig)
                        ├── RPi firmware + DTBs (3B/3B+/CM3)
                        ├── systemd init
                        ├── nftables + iproute2 (BalanSir runtime deps)
                        ├── balansir package (daemon/executor/cli, cargo)
                        └── genimage → sdcard.img (boot.vfat 64M + rootfs.ext4 256M)
```

## Repo layout

```text
buildroot-external/
├── external.desc                 BR2_EXTERNAL descriptor
├── external.mk
├── Config.in
├── configs/balansir_rpi3b_64_defconfig
├── package/balansir/             Buildroot package (cargo-package)
└── board/raspberrypi3/
    ├── rootfs-overlay/           /etc/balansir, systemd units, tmpfiles
    ├── post-build.sh             enable services, serial console, balansir user
    ├── post-image.sh             genimage wrapper
    └── genimage.cfg.in           SD card layout
tools/balansir-image/             Rust tool: inspect / checksum / qemu
deploy/buildroot/sync-to-vm.sh    ship repo snapshot into the build VM
```

## Build (fresh)

1. **Host tooling (once):**
   ```sh
   brew install qemu
   # aarch64 cloud image + NoCloud seed, boot the VM (see VM section)
   ```
2. **In the VM:**
   ```sh
   # Buildroot + deps
   sudo apt-get install -y build-essential gcc g++ make flex bison bc \
       libssl-dev libncurses-dev unzip cpio rsync wget file patch python3 git
   curl -L -o buildroot.tar.xz \
       https://buildroot.org/downloads/buildroot-2025.02.16.tar.xz
   tar xf buildroot.tar.xz

   # Repo (from host: deploy/buildroot/sync-to-vm.sh)
   cd buildroot-2025.02.16
   make BR2_EXTERNAL=/home/builder/buildroot-external balansir_rpi3b_64_defconfig
   make BR2_EXTERNAL=/home/builder/buildroot-external -j4
   ```
3. **Artifacts:** `output/images/sdcard.img`, `Image`, DTBs, `rootfs.ext4`.

## VM setup (macOS host, no admin)

```sh
# Ubuntu arm64 cloud image + NoCloud seed (user-data with your SSH key)
curl -L -o ubuntu-arm64.img \
    https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img
qemu-img create -f qcow2 -F qcow2 -b ubuntu-arm64.img ubuntu-work.qcow2 8G
# seed.iso: hdiutil makehybrid of {user-data, meta-data} (cidata)
qemu-system-aarch64 -M virt -cpu max -m 4G -smp 4 \
    -bios /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    -drive file=ubuntu-work.qcow2,if=none,id=hd0 -device virtio-blk-device,drive=hd0 \
    -drive file=seed.iso,media=cdrom,if=none,id=cd0 -device virtio-scsi-device,id=scsi -device scsi-cd,drive=cd0 \
    -netdev user,id=net0,hostfwd=tcp::2222-:22 -device virtio-net-device,netdev=net0 \
    -display none -serial file:serial.log -monitor none -daemonize -pidfile vm.pid
ssh -p 2222 builder@localhost
```

## Verification labels

| Item | Status |
|---|---|
| BalanSir cross-build (aarch64 musl static, host) | VERIFIED (ADR-029) |
| Buildroot external tree configures | VERIFIED (defconfig applied) |
| Buildroot full image build | IN PROGRESS |
| QEMU boot of sdcard.img (raspi3b machine) | PENDING |
| QEMU `virt` network boot test (init → network → executor → daemon → config) | PENDING |
| Real Raspberry Pi 3B+ | NOT HARDWARE VERIFIED (human step) |

Every label is assigned strictly: QEMU results are never claimed as hardware
verification.
