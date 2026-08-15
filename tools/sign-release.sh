#!/usr/bin/env bash
# OTA Release Signing Tool
#
# Creates a signed OTA release from a firmware image.
#
# Usage: ./sign-release.sh <firmware.img> <version> <channel> <target_device> <output_dir>

set -euo pipefail

FIRMWARE_IMAGE="${1:-}"
VERSION="${2:-}"
CHANNEL="${3:-stable}"
TARGET_DEVICE="${4:-rpi3b}"
OUTPUT_DIR="${5:-./releases}"

if [[ -z "$FIRMWARE_IMAGE" || -z "$VERSION" ]]; then
    echo "Usage: $0 <firmware.img> <version> [channel] [target_device] [output_dir]"
    exit 1
fi

if [[ ! -f "$FIRMWARE_IMAGE" ]]; then
    echo "Error: Firmware image not found: $FIRMWARE_IMAGE"
    exit 1
fi

# Load signing key from environment or file
PRIVATE_KEY_B64="${OTA_PRIVATE_KEY:-}"
if [[ -z "$PRIVATE_KEY_B64" && -f "$HOME/.balansir/ota-key" ]]; then
    PRIVATE_KEY_B64=$(cat "$HOME/.balansir/ota-key")
fi

if [[ -z "$PRIVATE_KEY_B64" ]]; then
    echo "Error: Signing key not provided. Set OTA_PRIVATE_KEY or create ~/.balansir/ota-key"
    exit 1
fi

# Decode private key
PRIVATE_KEY=$(echo "$PRIVATE_KEY_B64" | base64 -d)

# Compress firmware
COMPRESSED="${OUTPUT_DIR}/firmware-${VERSION}.img.xz"
echo "Compressing firmware..."
xz -c "$FIRMWARE_IMAGE" > "$COMPRESSED"

# Calculate size and hash
SIZE=$(stat -c%s "$COMPRESSED")
SHA256=$(sha256sum "$COMPRESSED" | cut -d' ' -f1)

# Generate key ID
KEY_ID="prod-$(date +%Y-%m)"

# Create manifest
MANIFEST="${OUTPUT_DIR}/manifest-${VERSION}.toml"
cat > "$MANIFEST" <<EOF
version = 1
firmware_version = "${VERSION}"
target_device = "${TARGET_DEVICE}"
channel = "${CHANNEL}"
min_version = ""

[image]
url = "https://updates.balansir.example.com/${CHANNEL}/${TARGET_DEVICE}/firmware-${VERSION}.img.xz"
size = ${SIZE}
sha256 = "${SHA256}"
compression = "xz"

[signature]
algorithm = "ed25519"
key_id = "${KEY_ID}"
signature = ""
EOF

# Sign manifest
# Canonicalize: remove signature field
CANONICAL=$(grep -v '^signature' "$MANIFEST" | head -n -1)
SIGNATURE=$(echo -n "$CANONICAL" | openssl dgst -sha256 -sign <(echo "$PRIVATE_KEY" | base64 -d) | openssl base64 -A)

# Update manifest with signature
sed -i "s/signature = \"\"/signature = \"${SIGNATURE}\"/" "$MANIFEST"

echo "Release created:"
echo "  Image: $COMPRESSED"
echo "  Manifest: $MANIFEST"
echo "  Version: $VERSION"
echo "  Size: $SIZE bytes"
echo "  SHA256: $SHA256"
echo "  Key ID: $KEY_ID"