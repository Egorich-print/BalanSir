# BalanSir Mission Context (session checkpoint)

## Goal
Reproducible Buildroot embedded image for Raspberry Pi 3B+ (aarch64) running
BalanSir network policy engine + operator tools. Full pipeline: source →
Buildroot external tree → kernel/DTB/rootfs → SD image → QEMU verify →
hardware flash.

## Current status (as of this checkpoint)

### Done / VERIFIED
- Buildroot 2026.05.1 external tree (`buildroot-external/`) in the BalanSir repo.
- QEMU-virt image (balansir_qemu_virt_defconfig): full-stack VERIFIED —
  boot→systemd→eth0 DHCP→executor+daemon active→/run/balansir sockets
  (split UID)→config loaded (fingerprint 0xdaa1…, desired rules:1)→
  balansir-cli status OK→nft v1.1.4.
- Operator tools added + VERIFIED in QEMU: tailscale 1.78.1, btop 1.4.7,
  fastfetch 2.67.0, OpenSSH 10.3p1.
- balansir-image Rust tool (inspect/checksum/verify/collect). QEMU test
  scripts. docs/BUILDROOT_IMAGE.md.
- Fixed BalanSir deploy bugs (ADR-030): Type=simple, auth default
  [0,1500], tmpfiles /run/balansir, /usr/local/bin install, PATH symlinks,
  removed stale scripts/balansir-cli.

### In progress
- RPi 3B+ image (balansir_rpi3b_64_defconfig) BUILDING in QEMU Ubuntu VM
  (ssh builder@localhost -p 2222, buildroot at /home/builder/buildroot-2026.05.1,
  output O=/home/builder/br-rpi, log /tmp/br-rpi.log). Was at busybox stage.
  This RPi build started BEFORE the UART-debug + getty defconfig edits were
  applied — a defconfig re-apply + rebuild is needed to include them.
- Just added (committed, sync'd to VM): RPi UART debug console
  (config_3_64bit.txt enable_uart=1, custom cmdline.txt loglevel=8
  systemd.log_level=debug, getty ttyAMA0@115200), persistent journal.

### Hardware available NOW
- SD card inserted in Mac: /dev/disk4, 31GB, SDXC reader (Built In SDXC
  Reader), 512-byte blocks, NOT read-only.
- Raspberry Pi 3B+ POWERED ON, connected to Mac via UART USB adapter at
  /dev/cu.usbserial-A5069RR4. **No SD card in the Pi.** UART is live to the
  Mac — can be used for boot observation once an image is flashed.

### Open items / decisions
1. **Verify RPi3B+ UART boot config correctness** — user reports RPi3B+
   UART boot did NOT work in Vivanta; must confirm our config.txt + cmdline.txt
   + getty setup is right for RPi3B+ (ttyAMA0 vs ttyAMA1, miniuart-bt,
   enable_uart, cmdline console=). Use sub-agents (check
   /Users/egorich/ai-workstation/Projects/Vivanta for their RPi UART config).
2. Finish RPi build (re-apply defconfig with UART edits → rebuild → sdcard.img).
3. Flash sdcard.img to /dev/disk4 (destructive, needs confirmation — dd to
   /dev/disk4). Then insert into Pi, observe boot over UART at
   /dev/cu.usbserial-A5069RR4 (screen/minicom/serial).
4. Final report.

## Key paths
- Repo: /Users/egorich/ai-workstation/Projects/BalanSir
- Build VM: ssh -p 2222 builder@localhost (Ubuntu arm64 in QEMU)
- Mission artifacts: /Users/egorich/ai-workstation/BalanSir-mission/
- Vivanta (reference for RPi UART): /Users/egorich/ai-workstation/Projects/Vivanta
