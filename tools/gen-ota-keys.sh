#!/usr/bin/env bash
# Generate Ed25519 key pair for OTA signing

set -euo pipefail

OUTPUT_DIR="${1:-$HOME/.balansir}"

mkdir -p "$OUTPUT_DIR"

PRIVATE_KEY="${OUTPUT_DIR}/ota-key"
PUBLIC_KEY="${OUTPUT_DIR}/ota-key.pub"

if [[ -f "$PRIVATE_KEY" ]]; then
    echo "Keys already exist at $OUTPUT_DIR"
    exit 0
fi

# Generate Ed25519 key pair
openssl genpkey -algorithm ed25519 -out "$PRIVATE_KEY"

# Extract public key in base64
openssl pkey -in "$PRIVATE_KEY" -pubout -outform DER | base64 > "$PUBLIC_KEY"

# Also save private key in base64 for the signing tool
openssl pkey -in "$PRIVATE_KEY" -outform DER | base64 > "${OUTPUT_DIR}/ota-key"

chmod 600 "$PRIVATE_KEY" "${OUTPUT_DIR}/ota-key"
chmod 644 "$PUBLIC_KEY"

echo "Keys generated:"
echo "  Private key: $PRIVATE_KEY"
echo "  Private key (base64): ${OUTPUT_DIR}/ota-key"
echo "  Public key (base64): $PUBLIC_KEY"
echo ""
echo "Add to your firmware build:"
echo "  cp $PUBLIC_KEY /etc/balansir/ota-key.pub"
echo ""
echo "Set environment variable for signing:"
echo "  export OTA_PRIVATE_KEY=\$(cat ${OUTPUT_DIR}/ota-key)"