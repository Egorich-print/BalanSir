#!/bin/bash
# BalanSir OTA post-image: assemble the SD card image with A/B + persistent layout.
#
# Creates partition images directly (no genimage dependency).
# Partition layout:
#   p1: boot       (vfat, 64M)
#   p2: system-A   (ext4, 300M)  — initially active slot
#   p3: system-B   (ext4, 300M)  — OTA target slot
#   p4: persistent (ext4, remaining)

set -e

BOARD_DIR="$(dirname "$0")"
BUILD_DIR="${BUILD_DIR:-/home/builder/br-qemu/output/build}"
BINARIES_DIR="${BINARIES_DIR:-/home/builder/br-qemu/output/images}"

# Ensure host tools are on PATH (mcopy, mkdosfs, etc.)
HOST_DIR="${HOST_DIR:-/home/builder/br-qemu/host}"
export PATH="${HOST_DIR}/bin:${PATH}"

SD_SIZE_MB="${SD_SIZE_MB:-2048}"
BOOT_SIZE_MB=64
SYSTEM_SIZE_MB=300
OVERHEAD_MB=32
PERSISTENT_SIZE_MB=$((SD_SIZE_MB - BOOT_SIZE_MB - SYSTEM_SIZE_MB * 2 - OVERHEAD_MB))

if [ "${PERSISTENT_SIZE_MB}" -lt 64 ]; then
    echo "ERROR: SD card too small for A/B + persistent layout (need >= 700MB, got ${SD_SIZE_MB}MB)" >&2
    exit 1
fi

echo "OTA partition layout:"
echo "  boot:       ${BOOT_SIZE_MB}MB (vfat)"
echo "  system-A:   ${SYSTEM_SIZE_MB}MB (ext4)"
echo "  system-B:   ${SYSTEM_SIZE_MB}MB (ext4)"
echo "  persistent: ${PERSISTENT_SIZE_MB}MB (ext4)"
echo "  total:      ${SD_SIZE_MB}MB"

BOOT_IMG="${BINARIES_DIR}/boot.vfat"
SYS_A_IMG="${BINARIES_DIR}/system-A.ext4"
SYS_B_IMG="${BINARIES_DIR}/system-B.ext4"
PERSIST_IMG="${BINARIES_DIR}/persistent.ext4"
SD_IMG="${BINARIES_DIR}/sdcard.img"

# --- 1. Boot partition (vfat) ---
echo ">> creating boot.vfat (${BOOT_SIZE_MB}MB)"
BOOT_SECTORS=$((BOOT_SIZE_MB * 2048))
mkdosfs -F 32 -n boot -C "${BOOT_IMG}" "${BOOT_SECTORS}"

# Copy boot files (no -s flag: it's for directories, not files)
MTOOLS_SKIP_CHECK=1
export MTOOLS_SKIP_CHECK
for i in "${BINARIES_DIR}"/*.dtb; do
    [ -f "$i" ] && mcopy -p -i "${BOOT_IMG}" "$i" "::$(basename "$i")"
done
for i in "${BINARIES_DIR}"/rpi-firmware/*; do
    [ -d "$i" ] && mcopy -sp -i "${BOOT_IMG}" "$i" "::$(basename "$i")" || \
    [ -f "$i" ] && mcopy -p -i "${BOOT_IMG}" "$i" "::$(basename "$i")"
done
KERNEL=$(sed -n 's/^kernel=//p' "${BINARIES_DIR}/rpi-firmware/config.txt")
mcopy -p -i "${BOOT_IMG}" "${BINARIES_DIR}/${KERNEL}" "::${KERNEL}"

# Copy cmdline-A.txt as default cmdline.txt
cp "${BOARD_DIR}/cmdline-A.txt" "${BINARIES_DIR}/cmdline.txt"
mcopy -p -i "${BOOT_IMG}" "${BINARIES_DIR}/cmdline.txt" "::cmdline.txt"

echo "   boot.vfat: $(ls -lh "${BOOT_IMG}" | awk '{print $5}')"

# --- 2. System-A (ext4, from rootfs) ---
echo ">> creating system-A.ext4 (${SYSTEM_SIZE_MB}MB)"
cp "${BINARIES_DIR}/rootfs.ext2" "${SYS_A_IMG}"
# Truncate to target partition size first, then resize filesystem
truncate -s "${SYSTEM_SIZE_MB}M" "${SYS_A_IMG}"
# Ensure filesystem is clean before resize
e2fsck -f -y "${SYS_A_IMG}" 2>/dev/null || true
resize2fs -f "${SYS_A_IMG}" 2>/dev/null || true

# --- 3. System-B (ext4, empty) ---
echo ">> creating system-B.ext4 (${SYSTEM_SIZE_MB}MB)"
dd if=/dev/zero of="${SYS_B_IMG}" bs=1M count="${SYSTEM_SIZE_MB}" status=none
mkfs.ext4 -F -L system-B "${SYS_B_IMG}" 2>/dev/null

# --- 4. Persistent (ext4, empty) ---
echo ">> creating persistent.ext4 (${PERSISTENT_SIZE_MB}MB)"
dd if=/dev/zero of="${PERSIST_IMG}" bs=1M count="${PERSISTENT_SIZE_MB}" status=none
mkfs.ext4 -F -L persistent "${PERSIST_IMG}" 2>/dev/null

# --- 5. Assemble sdcard.img ---
echo ">> assembling sdcard.img (${SD_SIZE_MB}MB)"
dd if=/dev/zero of="${SD_IMG}" bs=1M count="${SD_SIZE_MB}" status=progress 2>/dev/null

# Write MBR partition table
SEC_PER_MB=2048
P1_START=2048
P1_SIZE=$((BOOT_SIZE_MB * SEC_PER_MB))
P2_START=$((P1_START + P1_SIZE))
P2_SIZE=$((SYSTEM_SIZE_MB * SEC_PER_MB))
P3_START=$((P2_START + P2_SIZE))
P3_SIZE=$((SYSTEM_SIZE_MB * SEC_PER_MB))
P4_START=$((P3_START + P3_SIZE))
P4_SIZE=$((PERSISTENT_SIZE_MB * SEC_PER_MB))

sfdisk --quiet "${SD_IMG}" << EOF
label: dos
label-id: 0xBALANS1R
unit: sectors

${SD_IMG}1 : start=${P1_START}, size=${P1_SIZE}, type=c, bootable
${SD_IMG}2 : start=${P2_START}, size=${P2_SIZE}, type=83
${SD_IMG}3 : start=${P3_START}, size=${P3_SIZE}, type=83
${SD_IMG}4 : start=${P4_START}, size=${P4_SIZE}, type=83
EOF

# Write partition data
dd if="${BOOT_IMG}"    of="${SD_IMG}" bs=512 seek=${P1_START} count=${P1_SIZE} conv=notrunc status=none
dd if="${SYS_A_IMG}"   of="${SD_IMG}" bs=512 seek=${P2_START} count=${P2_SIZE} conv=notrunc status=none
dd if="${SYS_B_IMG}"   of="${SD_IMG}" bs=512 seek=${P3_START} count=${P3_SIZE} conv=notrunc status=none
dd if="${PERSIST_IMG}" of="${SD_IMG}" bs=512 seek=${P4_START} count=${P4_SIZE} conv=notrunc status=none

echo ">> sdcard.img assembled: ${SD_IMG}"
ls -lh "${SD_IMG}"
sha256sum "${SD_IMG}"

exit 0
