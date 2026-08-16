# BalanSir Raspberry Pi 3B+ Deployment Guide

**Date**: 2026-08-17

## Overview

BalanSir on RPi 3B+ acts as a transparent gateway between ISP and LAN:

```
ISP
 ↓
USB Ethernet WAN (enx*)
 ↓
RPi 3B+ / BalanSir (192.168.3.2)
 ↓ built-in eth0
HUAWEI AX3 (192.168.3.1, AP/bridge, no NAT)
 ↓
LAN clients (192.168.3.0/24)
```

## Build

### Prerequisites

- macOS or Linux host
- SSH access to BuildRoot VM on port 2222
- QEMU builder at `/home/builder/br-qemu`

### Steps

```bash
# 1. Sync code to BuildRoot VM (only after committing)
./deploy/buildroot/sync-to-vm.sh 2222

# 2. SSH into builder
ssh -p 2222 builder@localhost

# 3. Build
cd /home/builder/br-qemu
make balansir-rebuild all
```

### Output

After successful build, the image is at:

```
/home/builder/br-qemu/output/images/sdcard.img
```

Verify:

```bash
ls -la /home/builder/br-qemu/output/images/sdcard.img
sha256sum /home/builder/br-qemu/output/images/sdcard.img
```

## Partition Layout

The image uses A/B partition scheme for OTA:

| Partition | Mount | Purpose |
|-----------|-------|---------|
| mmcblk0p1 | /boot | Boot files, kernel, DTB |
| mmcblk0p2 | / (Slot A) | Root filesystem A |
| mmcblk0p3 | / (Slot B) | Root filesystem B |
| mmcblk0p4 | /persistent | Persistent config, OTA metadata |

## SD Card Preparation

### macOS

#### 1. Identify the SD card

```bash
diskutil list
```

Look for a removable disk matching your SD card size (typically 8-32GB). The device will be `/dev/diskN`.

Verify it's the correct device:

```bash
diskutil info /dev/diskN
```

Check:
- `Device Location`: External
- `Protocol`: USB or SD
- `Total Size`: matches your SD card
- `Device Node`: `/dev/diskN`

#### 2. Unmount the disk

```bash
diskutil unmountDisk /dev/diskN
```

#### 3. Write the image

Use the raw device (`/dev/rdiskN` for faster writes on macOS):

```bash
sudo dd if=sdcard.img of=/dev/rdiskN bs=4m status=progress
```

**WARNING**: Double-check the device! Writing to wrong disk will destroy data.

#### 4. Sync and eject

```bash
sync
diskutil eject /dev/diskN
```

### Linux

#### 1. Identify the SD card

```bash
lsblk
```

Look for a removable device matching your SD card size.

Verify:

```bash
sudo blkid /dev/sdX
```

#### 2. Unmount any mounted partitions

```bash
sudo umount /dev/sdX*
```

#### 3. Write the image

```bash
sudo dd if=sdcard.img of=/dev/sdX bs=4M status=progress conv=fsync
```

**WARNING**: Double-check the device!

#### 4. Sync

```bash
sync
```

## Post-Flash Verification

After writing, verify the partition table:

```bash
# macOS
diskutil list /dev/diskN

# Linux
sudo fdisk -l /dev/sdX
```

You should see 4 partitions matching the layout above.

## First Boot

### Physical Setup

1. Insert SD card into RPi 3B+
2. Connect USB Ethernet adapter (WAN) to ISP/modem
3. Connect built-in eth0 (LAN) to HUAWEI AX3
4. Connect USB power

### Network Configuration

RPi will come up with:
- LAN IP: `192.168.3.2` (from network.toml)
- WAN: DHCP from ISP

### Access

From a LAN client connected to AX3:

```bash
# SSH (port 22)
ssh root@192.168.3.2

# WebUI (needs BALANSIR_API_BIND=0.0.0.0:8080 in config)
curl http://192.168.3.2:8080/system

# API health check
curl http://192.168.3.2:8080/health

# DNS (port 53)
dig @192.168.3.2 example.com
```

### LAN Management Access

The management firewall allows LAN → RPi on ports {22, 53, 8080, 9090} and blocks WAN → RPi.

For WebUI/API to be accessible from LAN, the API must bind to the LAN interface. In `/etc/balansir/balansir.toml`:

```toml
[api]
enabled = true
bind = "0.0.0.0:8080"
```

Or set environment variable:

```bash
export BALANSIR_API_BIND=0.0.0.0:8080
```

### Gateway Verification

```bash
# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward
# Should be: 1

# Check NAT rules
nft list ruleset

# Check interfaces
ip addr show

# Check routes
ip route show
```

### MAC Clone Verification

If WAN MAC cloning is configured in `network.toml`:

```bash
# Check WAN interface MAC
ip link show <wan_interface>
# Should show: 90:98:38:52:AE:79 (or configured MAC)
```

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/balansir/balansir.toml` | Main daemon config |
| `/etc/balansir/network.toml` | WAN/LAN roles, MAC cloning |
| `/etc/balansir/dns.toml` | DNS upstreams, blocklist |
| `/etc/balansir/xray.toml` | Xray VPN profiles |
| `/etc/balansir/vpn.toml` | VPN pool config |

## Systemd Services

```bash
# Check daemon status
systemctl status balansir-daemon

# Check executor status
systemctl status balansir-executor

# View logs
journalctl -u balansir-daemon -f
journalctl -u balansir-executor -f
```

## Troubleshooting

### No network connectivity

```bash
# Check interface status
ip link show

# Check routing
ip route show

# Check firewall rules
nft list ruleset

# Check daemon logs
journalctl -u balansir-daemon -n 50
```

### DNS not resolving

```bash
# Check DNS listener
ss -ulnp | grep :53

# Test DNS
dig @192.168.3.2 example.com

# Check DNS config
cat /etc/balansir/dns.toml
```

### WebUI not accessible

```bash
# Check API bind address
ss -tlnp | grep :8080

# Verify config
cat /etc/balansir/balansir.toml | grep -A5 "\[api\]"
```
