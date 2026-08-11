#!/bin/sh
# Build static aarch64 (Raspberry Pi 3B+/4B, arm64) BalanSir binaries.
#
# Requirements:
#   - Rust with the aarch64-unknown-linux-musl target:
#       rustup target add aarch64-unknown-linux-musl
#   - zig (used only as the GNU-style linker; it links musl statically):
#       brew install zig
#   - a `zig-cc` shim on PATH that invokes `zig cc -target aarch64-linux-musl`:
#       printf '#!/bin/sh\nexec zig cc -target aarch64-linux-musl "$@"\n' > /usr/local/bin/zig-cc
#       chmod +x /usr/local/bin/zig-cc
#
# Output: target/aarch64-unknown-linux-musl/release/{balansir-daemon,balansir-executor,balansir-cli}
# These are statically linked ELF aarch64 binaries — no glibc dependency on
# the target (musl), suitable for Raspberry Pi OS / Debian arm64.
#
# The linker + rustflags are also configured in .cargo/config.toml
# ([target.aarch64-unknown-linux-musl]); the env here is belt-and-suspenders.

set -euo pipefail

TARGET="aarch64-unknown-linux-musl"

if ! command -v zig-cc >/dev/null 2>&1; then
    echo "error: zig-cc shim not found on PATH" >&2
    echo "create it with: printf '#!/bin/sh\\nexec zig cc -target aarch64-linux-musl \"\$@\"\\n' > /usr/local/bin/zig-cc && chmod +x /usr/local/bin/zig-cc" >&2
    exit 1
fi

# link-self-contained=no: let zig provide musl libc/CRT instead of Rust's
# self-contained objects, avoiding a duplicate-crt link failure.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="zig-cc"
export RUSTFLAGS="-C link-self-contained=no"

echo "Building BalanSir for ${TARGET}..."
cargo build --release \
    --target "${TARGET}" \
    --bin balansir-daemon \
    --bin balansir-executor \
    --bin balansir-cli

OUT="target/${TARGET}/release"
echo
echo "Artifacts:"
for b in balansir-daemon balansir-executor balansir-cli; do
    file "${OUT}/${b}"
done
echo
echo "Done. Deploy with: deploy/rpi3b/install.sh <host>"
