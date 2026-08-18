#!/bin/sh
# BalanSir OTA post-image script
# Runs inside Buildroot after the rootfs is assembled (TARGET_DIR).
set -eu
TARGET_DIR="${1}"
SD_SIZE_MB="${SD_SIZE_MB:-0}"

# Check SD card size
if [ "${SD_SIZE_MB}" -lt 700 ]; then
    echo "ERROR: SD card too small for A/B + persistent layout (need >= 700MB, got ${SD_SIZE_MB}MB)" >&2
    exit 1
fi

# Generate initial boot script for slot A
cat > "${TARGET_DIR}/boot/cmdline.txt" << EOF
root=/dev/mmcblk0p2 rootwait console=tty1 console=serial0,115200 loglevel=8 consoleblank=0 systemd.log_level=debug net.ifnames=0 biosdevname=0 balansir_slot=A
EOF

# Ensure persistent directory exists
mkdir -p "${TARGET_DIR}/persistent"

echo "A/B + persistent layout installed successfully"
