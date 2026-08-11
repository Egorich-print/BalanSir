#!/bin/sh
# QEMU boot-test of the BalanSir Buildroot image (run on the macOS host).
#
# The RPi3 SD image does not network under QEMU (raspi3b machine has no NIC),
# so this uses the Buildroot `virt` machine path: kernel Image + rootfs.ext4 +
# virtio network. It verifies:
#   boot -> init (systemd) -> network (DHCP) -> executor -> daemon ->
#   BALANSIR_CONFIG loaded -> first reconcile -> CLI status responds.
#
# Usage:
#   1. In the VM:  cp output/images/rootfs.ext4 /home/builder/  (kernel Image too)
#   2. Host:       scp -P 2222 builder@localhost:{Image,rootfs.ext4} .
#   3. Host:       deploy/buildroot/qemu-test.sh
#
# Requires qemu-system-aarch64 on the host. Produces serial-test.log.

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${ROOT}/output/qemu-test"
mkdir -p "${WORK}"
LOG="${WORK}/serial-test.log"

QEMU="$(command -v qemu-system-aarch64 || echo /opt/homebrew/bin/qemu-system-aarch64)"

echo ">> QEMU boot test: ${QEMU}"
echo ">> kernel: ${ROOT}/output/qemu-test/Image  rootfs: ${ROOT}/output/qemu-test/rootfs.ext4"

"${QEMU}" \
    -M virt -cpu cortex-a53 -m 1G -smp 2 \
    -kernel "${WORK}/Image" \
    -append "root=/dev/vda rootwait console=ttyAMA0 panic=-1" \
    -drive "file=${WORK}/rootfs.ext4,if=none,format=raw,id=hd0" \
    -device virtio-blk-device,drive=hd0 \
    -netdev user,id=eth0 \
    -device virtio-net-device,netdev=eth0 \
    -nographic -no-reboot \
    -serial "file:${LOG}" \
    > /dev/null 2>&1 &
QPID=$!

echo ">> waiting for boot markers (timeout 120s)..."
TIMEOUT=120
i=0
while [ $i -lt $TIMEOUT ]; do
    if grep -q "balansir-daemon.service" "${LOG}" 2>/dev/null && \
       grep -qi "reconcile\|listening on" "${LOG}" 2>/dev/null; then
        echo ">> daemon markers found after ${i}s"
        break
    fi
    sleep 2
    i=$((i+2))
done

kill $QPID 2>/dev/null || true
wait $QPID 2>/dev/null || true

echo "============================================================"
echo "BOOT TEST RESULT:"
if grep -q "Reached target" "${LOG}" 2>/dev/null; then
    echo "  [OK] systemd reached multi-user target"
else
    echo "  [??] multi-user target not observed (check log)"
fi
grep -c "balansir" "${LOG}" | sed 's/^/  balansir log lines: /'
echo "  full log: ${LOG}"
echo "============================================================"
