#!/bin/bash
# BalanSir post-image: assemble the SD card image with genimage.
#
# Based on Buildroot's raspberrypi3-64 post-image.sh; the genimage config is
# generated directly (no placeholder substitution, avoiding sed/awk newline
# issues).

set -e

BOARD_DIR="$(dirname "$0")"
GENIMAGE_CFG="${BOARD_DIR}/genimage.cfg"
GENIMAGE_TMP="${BUILD_DIR}/genimage.tmp"

FILES=()
for i in "${BINARIES_DIR}"/*.dtb "${BINARIES_DIR}"/rpi-firmware/*; do
    FILES+=( "${i#${BINARIES_DIR}/}" )
done

KERNEL=$(sed -n 's/^kernel=//p' "${BINARIES_DIR}/rpi-firmware/config.txt")
FILES+=( "${KERNEL}" )
# cmdline.txt is installed by the rpi-firmware package into
# rpi-firmware/cmdline.txt (BR2_PACKAGE_RPI_FIRMWARE_CMDLINE_FILE), which is
# already in FILES via rpi-firmware/*.

# Write the genimage config, embedding the boot-file list directly.
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
    echo "	size = 64M"
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
    echo "	partition rootfs {"
    echo "		partition-type = 0x83"
    echo "		image = \"rootfs.ext4\""
    echo "	}"
    echo "}"
} > "${GENIMAGE_CFG}"

# Pass an empty rootpath: genimage only inserts the pre-built rootfs image.
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
