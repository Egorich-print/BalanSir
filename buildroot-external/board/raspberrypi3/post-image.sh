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

# Write genimage config
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
    echo "image system-A.ext4 {"
    echo "	ext4 {"
    echo "		base = \"rootfs.ext4\""
    echo "	}"
    echo ""
    echo "	size = ${SYSTEM_SIZE_MB}M"
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
    echo ""
    echo "image sdcard.img {"
    echo "	hdimage {"
    echo "	}"
    echo ""
    echo "	partition boot {"
    echo "		partition-type = 0xC"
    echo "		bootable = \"true\""
    echo "		image = \"boot.vfat\""
    echo "	}"
    echo ""
    echo "	partition system-A {"
    echo "		partition-type = 0x83"
    echo "		image = \"system-A.ext4\""
    echo "	}"
    echo ""
    echo "	partition system-B {"
    echo "		partition-type = 0x83"
    echo "		image = \"system-B.ext4\""
    echo "	}"
    echo ""
    echo "	partition persistent {"
    echo "		partition-type = 0x83"
    echo "		image = \"persistent.ext4\""
    echo "	}"
    echo "}"
} > "${GENIMAGE_CFG}"

# Run genimage
trap 'rm -rf "${ROOTPATH_TMP}"' EXIT
ROOTPATH_TMP="$(mktemp -d)"
rm -rf "${GENIMAGE_TMP}"

genimage \
    --rootpath "${ROOTPATH_TMP}"   \
    --tmppath "${GENIMAGE_TMP}"    \
    --inputpath "${BINARIES_DIR}"  \
    --outputpath "${BINARIES_DIR}" \
    --config "${GENIMAGE_CFG}"

exit $?