#!/bin/bash
# BalanSir OTA post-image: assemble the SD card image with A/B + persistent layout.
#
# Generates genimage config with dynamic partition sizing based on target image size.

set -e

BOARD_DIR="$(dirname "$0")"
BUILD_DIR="${BUILD_DIR:-/home/builder/br-qemu/output/build}"
BINARIES_DIR="${BINARIES_DIR:-/home/builder/br-qemu/output/images}"
GENIMAGE_TMP="${BUILD_DIR}/genimage.tmp"

# Read target SD card size from environment or default to 2GB (minimum for A/B)
# SD_SIZE_MB can be overridden: make SD_SIZE_MB=4096
SD_SIZE_MB="${SD_SIZE_MB:-2048}"

# Fixed sizes
BOOT_SIZE_MB=64
SYSTEM_SIZE_MB=300

# Calculate persistent partition size (remaining space)
# Total partitions: boot + system-A + system-B + persistent + alignment overhead
OVERHEAD_MB=32
PERSISTENT_SIZE_MB=$((SD_SIZE_MB - BOOT_SIZE_MB - SYSTEM_SIZE_MB * 2 - OVERHEAD_MB))

if [ ${PERSISTENT_SIZE_MB} -lt 64 ]; then
    echo "ERROR: SD card too small for A/B + persistent layout (need >= 700MB, got ${SD_SIZE_MB}MB)" >&2
    exit 1
fi

echo "OTA partition layout:"
echo "  boot:       ${BOOT_SIZE_MB}MB (vfat)"
echo "  system-A:   ${SYSTEM_SIZE_MB}MB (ext4)"
echo "  system-B:   ${SYSTEM_SIZE_MB}MB (ext4)"
echo "  persistent: ${PERSISTENT_SIZE_MB}MB (ext4)"
echo "  total:      ${SD_SIZE_MB}MB"

# Collect boot files
FILES=()
for i in "${BINARIES_DIR}"/*.dtb "${BINARIES_DIR}"/rpi-firmware/*; do
    FILES+=( "${i#${BINARIES_DIR}/}" )
done

KERNEL=$(sed -n 's/^kernel=//p' "${BINARIES_DIR}/rpi-firmware/config.txt")
FILES+=( "${KERNEL}" )

# Copy cmdline-A.txt as default cmdline.txt (Slot A boots first)
cp "${BOARD_DIR}/cmdline-A.txt" "${BINARIES_DIR}/cmdline.txt"
FILES+=( "cmdline.txt" )

# Copy rootfs as system-A (the initially active slot).
# system-B and persistent start empty (genimage creates them at target size).
cp "${BINARIES_DIR}/rootfs.ext4" "${BINARIES_DIR}/system-A.src"

# Write genimage config for boot, system-B, persistent.
# system-A is pre-built from rootfs.ext4; we assemble the final sdcard.img
# ourselves with dd (genimage v19 doesn't support 'base' for ext4).
GENIMAGE_CFG="${BOARD_DIR}/genimage-ota.cfg"
{
    echo "image boot.vfat {"
    echo "	vfat {"
    echo "		files = {"
    for f in "${FILES[@]}"; do
        printf '\t\t\t"%s",\n' "$f"
    done
    echo "		}"
    echo "	}"
    echo ""
    echo "	size = ${BOOT_SIZE_MB}M"
    echo "}"
    echo ""
    echo "image system-B.ext4 {"
    echo "	ext4 {"
    echo "	}"
    echo ""
    echo "	size = ${SYSTEM_SIZE_MB}M"
    echo "}"
    echo ""
    echo "image persistent.ext4 {"
    echo "	ext4 {"
    echo "	}"
    echo ""
    echo "	size = ${PERSISTENT_SIZE_MB}M"
    echo "}"
} > "${GENIMAGE_CFG}"

# Run genimage
trap 'rm -rf "${ROOTPATH_TMP}"' EXIT
ROOTPATH_TMP="$(mktemp -d)"
rm -rf "${GENIMAGE_TMP}"

# Use host genimage from Buildroot output
GENIMAGE="${HOST_DIR:-/home/builder/br-qemu/host}/bin/genimage"
# Ensure host tools (mcopy, mkdosfs, etc.) are on PATH
export PATH="${HOST_DIR:-/home/builder/br-qemu/host}/bin:${PATH}"
"${GENIMAGE}" \
    --rootpath "${ROOTPATH_TMP}"   \
    --tmppath "${GENIMAGE_TMP}"    \
    --inputpath "${BINARIES_DIR}"  \
    --outputpath "${BINARIES_DIR}" \
    --config "${GENIMAGE_CFG}"

# Assemble sdcard.img with dd.
# Layout: boot.vfat | system-A.ext4 | system-B.ext4 | persistent.ext4
IMG="${BINARIES_DIR}/sdcard.img"
BOOT="${BINARIES_DIR}/boot.vfat"
SYS_A="${BINARIES_DIR}/system-A.src"
SYS_B="${BINARIES_DIR}/system-B.ext4"
PERSIST="${BINARIES_DIR}/persistent.ext4"

# Verify all parts exist
for f in "${BOOT}" "${SYS_A}" "${SYS_B}" "${PERSIST}"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: missing image part: $f" >&2
        exit 1
    fi
done

# Create sdcard.img
dd if=/dev/zero of="${IMG}" bs=1M count="${SD_SIZE_MB}" status=none

# Write MBR partition table
# Partition layout (all sectors are 512 bytes):
#   p1: boot       type=0x0C (FAT32 LBA)  bootable
#   p2: system-A   type=0x83 (Linux)
#   p3: system-B   type=0x83 (Linux)
#   p4: persistent type=0x83 (Linux)
#   p1 start=2048 (1MB), size=BOOT_SIZE_MB*2048 sectors
#   p2 start after p1, size=SYSTEM_SIZE_MB*2048 sectors
#   p3 start after p2, size=SYSTEM_SIZE_MB*2048 sectors
#   p4 start after p3, rest

SEC_PER_MB=2048
P1_START=2048
P1_SIZE=$((BOOT_SIZE_MB * SEC_PER_MB))
P2_START=$((P1_START + P1_SIZE))
P2_SIZE=$((SYSTEM_SIZE_MB * SEC_PER_MB))
P3_START=$((P2_START + P2_SIZE))
P3_SIZE=$((SYSTEM_SIZE_MB * SEC_PER_MB))
P4_START=$((P3_START + P3_SIZE))
P4_SIZE=$(((SD_SIZE_MB - BOOT_SIZE_MB - SYSTEM_SIZE_MB * 2) * SEC_PER_MB))

# Write partition table
sfdisk --quiet "${IMG}" << EOF
label: dos
label-id: 0xBALANS1R
unit: sectors

${IMG}1 : start=${P1_START}, size=${P1_SIZE}, type=c, bootable
${IMG}2 : start=${P2_START}, size=${P2_SIZE}, type=83
${IMG}3 : start=${P3_START}, size=${P3_SIZE}, type=83
${IMG}4 : start=${P4_START}, size=${P4_SIZE}, type=83
EOF

# Write partition images
dd if="${BOOT}"   of="${IMG}" bs=512 seek=${P1_START} count=${P1_SIZE} conv=notrunc status=none
dd if="${SYS_A}"  of="${IMG}" bs=512 seek=${P2_START} count=${P2_SIZE} conv=notrunc status=none
dd if="${SYS_B}"  of="${IMG}" bs=512 seek=${P3_START} count=${P3_SIZE} conv=notrunc status=none
dd if="${PERSIST}" of="${IMG}" bs=512 seek=${P4_START} count=${P4_SIZE} conv=notrunc status=none

echo ">> sdcard.img assembled: ${IMG}"
ls -lh "${IMG}"

exit 0