#!/bin/sh
# Sync the BalanSir repository snapshot into the Buildroot build VM (QEMU).
#
# The VM is Ubuntu arm64 cloud image booted under qemu-system-aarch64 -M virt
# (see docs/BUILDROOT_IMAGE.md). Buildroot only runs on Linux; this script
# ships the current checkout (git-tracked files only) into the VM so
# `buildroot-external` changes are picked up without re-cloning.
#
# Usage: deploy/buildroot/sync-to-vm.sh [ssh-port]   (default port 2222)
#
# Host requirement: SSH key auth to builder@localhost:PORT already set up.
#
# Integrity (mission §20): the snapshot carries a marker with the host HEAD
# SHA; after extraction the VM echoes it back and the script refuses to proceed
# unless it matches the host. A dirty working tree is warned about loudly —
# uncommitted changes are not in `git archive HEAD` and would silently test an
# older tree.

set -eu

PORT="${1:-2222}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo ">> creating snapshot from git tree (tracked files only)"
HOST_SHA="$(git -C "$ROOT" rev-parse HEAD)"

# Warn on a dirty tree: uncommitted files are not in `git archive HEAD`, so
# verification would silently test a stale snapshot. Explicit, not silent.
if git -C "$ROOT" status --porcelain | grep -q .; then
    echo "!! WARNING: working tree is DIRTY — uncommitted changes will NOT be"
    echo "!! shipped to the VM (git archive uses HEAD only). Commit first or"
    echo "!! the VM will build a stale tree."
else
    echo ">> tree clean (HEAD ${HOST_SHA})"
fi

git -C "$ROOT" archive --format=tar HEAD | tar -xf - -C "$TMP"
# Marker carrying the exact host HEAD (uncommitted files are not in it).
printf '%s\n' "$HOST_SHA" > "$TMP/.snapshot-sha"

echo ">> shipping to builder@localhost:${PORT}"
# Create the archive OUTSIDE the snapshot dir (avoid adding the archive to
# itself), then copy it into the VM's repo dir.
(cd "$TMP" && COPYFILE_DISABLE=1 tar czf "$TMP.tgz" .)
scp -q -o StrictHostKeyChecking=no -P "$PORT" "$TMP.tgz" \
    "builder@localhost:/home/builder/balansir/snapshot.tgz"

ssh -o StrictHostKeyChecking=no -p "$PORT" builder@localhost '
    set -eu
    cd /home/builder/balansir
    rm -rf buildroot-external Cargo.toml Cargo.lock crates config deploy docs tools Makefile *.md *.sh
    COPYFILE_DISABLE=1 tar xzf snapshot.tgz
    rm -f snapshot.tgz
    echo ">> synced: $(ls buildroot-external/configs/)"
'

# Verify the VM received exactly the host's HEAD via the embedded marker.
VM_SHA="$(ssh -o StrictHostKeyChecking=no -p "$PORT" builder@localhost \
    'cat /home/builder/balansir/.snapshot-sha 2>/dev/null || echo NO_MARKER')"

echo ">> HOST HEAD: $HOST_SHA"
echo ">> VM HEAD:   $VM_SHA"
if [ "$HOST_SHA" = "$VM_SHA" ]; then
    echo ">> OK: matching snapshot (host HEAD == VM snapshot)"
else
    echo "!! ERROR: snapshot mismatch — the VM does NOT hold the host HEAD."
    echo "!! Refusing to proceed on a mismatched tree."
    exit 1
fi

rm -f "$TMP.tgz"
echo ">> done"
