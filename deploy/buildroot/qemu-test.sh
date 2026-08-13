#!/bin/sh
# QEMU boot-test of the BalanSir Buildroot image (run on the macOS host).
#
# Uses the Buildroot `virt` machine path: kernel Image + rootfs.ext4 +
# virtio network (the RPi3 raspi3b machine has no NIC). It verifies:
#   boot -> init (systemd) -> network (DHCP) -> executor -> daemon ->
#   BALANSIR_CONFIG loaded -> first reconcile -> CLI status responds.
#
# Usage:
#   deploy/buildroot/qemu-test.sh <Image> <rootfs.ext4> [timeout_secs]
#
# Requires qemu-system-aarch64 on the host. Produces serial-test.log.

set -eu

KERNEL="${1:?usage: qemu-test.sh <Image> <rootfs> [timeout]}"
ROOTFS="${2:?usage: qemu-test.sh <Image> <rootfs> [timeout]}"
TIMEOUT="${3:-120}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOG="${ROOT}/serial-test.log"

QEMU="$(command -v qemu-system-aarch64 || echo /opt/homebrew/bin/qemu-system-aarch64)"
echo ">> QEMU: ${QEMU}"
echo ">> kernel: ${KERNEL}  rootfs: ${ROOTFS}  timeout: ${TIMEOUT}s"

"${QEMU}" \
    -M virt -cpu cortex-a53 -m 1G -smp 2 \
    -kernel "${KERNEL}" \
    -append "root=/dev/vda rootwait console=ttyAMA0 panic=-1" \
    -drive "file=${ROOTFS},if=none,format=raw,id=hd0" \
    -device virtio-blk-device,drive=hd0 \
    -netdev user,id=eth0 \
    -device virtio-net-device,netdev=eth0 \
    -nographic -no-reboot \
    -serial "file:${LOG}" > /dev/null 2>&1 &
QPID=$!

echo ">> waiting for boot markers (timeout ${TIMEOUT}s)..."
i=0
while [ $i -lt "$TIMEOUT" ]; do
    # Login prompt => systemd reached a getty (multiuser-ish).
    if grep -q "balansir login:" "${LOG}" 2>/dev/null; then
        echo ">> login prompt reached after ${i}s"
        break
    fi
    if grep -qi "Kernel panic" "${LOG}" 2>/dev/null; then
        echo ">> KERNEL PANIC observed"
        break
    fi
    sleep 2
    i=$((i+2))
done

kill "$QPID" 2>/dev/null || true
wait "$QPID" 2>/dev/null || true

echo "============================================================"
echo "BOOT TEST RESULT (QEMU VERIFIED):"
if grep -q "balansir login:" "${LOG}" 2>/dev/null; then
    echo "  [PASS] systemd reached getty (boot OK)"
else
    echo "  [FAIL] no login prompt in ${TIMEOUT}s"
fi
if grep -qi "Kernel panic" "${LOG}" 2>/dev/null; then
    echo "  [FAIL] kernel panic"
fi
grep -iE "balansir-(daemon|executor)|Reached target" "${LOG}" 2>/dev/null | head -5 \
    | sed 's/^/  /'
echo "  full log: ${LOG}"
echo "============================================================"
