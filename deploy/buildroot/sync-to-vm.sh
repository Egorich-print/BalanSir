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

set -eu

PORT="${1:-2222}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo ">> creating snapshot from git tree (tracked files only)"
git -C "$ROOT" archive --format=tar HEAD | tar -xf - -C "$TMP"

echo ">> shipping to builder@localhost:${PORT}"
COPYFILE_DISABLE=1 tar czf "$TMP/snapshot.tgz" -C "$TMP" .
scp -q -o StrictHostKeyChecking=no -P "$PORT" "$TMP/snapshot.tgz" \
    "builder@localhost:/home/builder/"

ssh -o StrictHostKeyChecking=no -p "$PORT" builder@localhost '
    set -eu
    cd /home/builder/balansir
    rm -rf buildroot-external Cargo.toml Cargo.lock crates config deploy docs tools Makefile *.md *.sh
    COPYFILE_DISABLE=1 tar xzf snapshot.tgz
    rm -f snapshot.tgz
    echo ">> synced: $(ls buildroot-external/configs/)"
'

echo ">> done"
