#!/usr/bin/env bash
# Full-stack BalanSir check inside QEMU via SSH (hostfwd).
#
# Boots qemu-system-aarch64 -M virt (virtio net/block) with hostfwd TCP 2223
# -> guest:22, waits for SSH, then runs the BalanSir health checks over ssh as
# root (key auth; the dev image ships the builder's authorized_keys).
#
# Usage: qemu-login-test.sh <Image> <rootfs.ext4> [timeout_secs]
# Requires: qemu-system-aarch64, ssh.

set -u
KERNEL="${1:?Image}"
ROOTFS="${2:?rootfs}"
TIMEOUT="${3:-120}"
SSH_PORT=2223
LOG="$(mktemp).serial.log"
QEMU="$(command -v qemu-system-aarch64 || echo /opt/homebrew/bin/qemu-system-aarch64)"

"$QEMU" -M virt -cpu cortex-a53 -m 1G -smp 2 \
    -kernel "$KERNEL" \
    -append "root=/dev/vda rootwait console=ttyAMA0 panic=-1 loglevel=8 systemd.log_level=debug" \
    -drive "file=$ROOTFS,if=none,format=raw,id=hd0" -device virtio-blk-device,drive=hd0 \
    -netdev "user,id=eth0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22" \
    -device virtio-net-device,netdev=eth0 \
    -display none -serial "file:$LOG" -no-reboot &
QPID=$!

echo ">> waiting for SSH on 127.0.0.1:${SSH_PORT} (timeout ${TIMEOUT}s)"
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 -p "$SSH_PORT" root@127.0.0.1 true 2>/dev/null
i=0
while [ $i -lt "$TIMEOUT" ]; do
    if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 -p "$SSH_PORT" root@127.0.0.1 true 2>/dev/null; then
        echo ">> SSH up after ${i}s"
        break
    fi
    sleep 2
    i=$((i+2))
done

SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $SSH_PORT root@127.0.0.1"

echo "============================================================"
echo "FULL-STACK RESULT (QEMU VERIFIED)"
for name_cmd in \
    "arch|uname -m" \
    "uid|id -u" \
    "services|systemctl is-active balansir-daemon balansir-executor" \
    "run|ls -la /run/balansir" \
    "cli-status|balansir-cli status" \
    "fingerprint|balansir-cli fingerprint" \
    "desired|balansir-cli desired" \
    "nft|nft --version" \
    "ifaces|ip -brief addr"; do
    name="${name_cmd%%|*}"
    cmd="${name_cmd#*|}"
    echo "--- $name ---"
    $SSH "$cmd" 2>&1 || echo "(ssh failed)"
done
echo "============================================================"

kill "$QPID" 2>/dev/null; wait "$QPID" 2>/dev/null
echo "serial log: $LOG"
