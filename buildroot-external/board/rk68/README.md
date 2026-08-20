# BalanSir RK68 (Rockchip RK3568) — initial support layer

Initial support for the Barebone RK68 / RK3568 board family
(`Rockchip RK3568 NVR DEMO DDR4 V12 Linux Board`, NVR304-32E2, revisions
4H/4G/8G). This is a **new target**; existing targets (RPi 3B+, QEMU virt)
are untouched.

## Hardware summary (from the Vivanta board reference)

- **SoC**: RK3568, 4× Cortex-A55 (AArch64), 4 GiB DDR4
- **Boot storage**: SPI NAND 128 MiB — kernel partition at `0xF80000`,
  12 MiB. **No SD rootfs.**
- **UART**: NS16550 @ `0xFE660000` (reg-shift 2), 115200 8N1, ttyS0
- **Ethernet**: eth0 `fe2a0000` (RJ45), eth1 `fe010000`
- **U-Boot**: `bootm` has **no FDT/ATAGS** → kernel must boot via `booti`
  (ARM64 Image) with DTB at `fdt_addr_r` (`0x0a100000`) or the internal
  control FDT (`0xebd753c0`). Kernel entry must disable the MMU at EL2 and
  drop to EL1 before any memory access.

Full hardware reference: `~/ai-workstation/Projects/Vivanta/docs/hardware/rk3568/board-info.md`.

## What this layer provides

- `configs/balansir_rk68_defconfig` — Buildroot target (aarch64, systemd,
  the full BalanSir feature stack: nftables, iproute2, iptables, openssh,
  iw, wpa_supplicant, BalanSir daemon/executor/OTA).
- `board/rk68/linux.fragment` — kernel fragment enabling the same network
  feature stack as the RPi target (USB Ethernet AX88179/RTL8156, USB Wi-Fi,
  MPTCP, QoS, nftables/NFQUEUE, TUN).
- `board/rk68/post-build.sh` — enables BalanSir units, serial getty on
  ttyS0, balansir user (UID 1500), state dirs.
- `board/rk68/rootfs-overlay/` — BalanSir config + systemd units.

## Build

```bash
make BR2_EXTERNAL=buildroot-external balansir_rk68_defconfig
make
```

## Deploy (boot flow)

The board boots a raw ARM64 `Image` from SPI NAND via `booti`:

```bash
# Build the kernel Image
make linux-rebuild linux
# Flash kernel to SPI NAND at 0xF80000, load DTB to 0x0a100000, then:
#   booti 0x20500000 - 0x0a100000
```

For the initial bring-up the rootfs can be served over NFS/TFTP; the board's
U-Boot has TFTP + DHCP (`tftp uImage_rk3568`, `booti`).

## OTA on RK68

The A/B slot model differs from the SD-based RPi target: here the "slot" is a
**kernel image slot** on SPI NAND (offset `0xF80000`, 12 MiB). The
`balansir-ota` installer's `Slot` abstraction (mmcblk0p2/p3) does not apply
to this boot model yet; the RK68 OTA layout (two kernel slots + boot-select
via the U-Boot `boot_flashkernel` backup addresses at `0x20000` intervals) is
the next step. The systemd/persistent layer is ready for the metadata.
