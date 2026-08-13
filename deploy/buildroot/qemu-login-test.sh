#!/usr/bin/env bash
# Full-stack BalanSir check inside QEMU: login + balansir-cli status/desired/
# fingerprint + verify daemon/executor processes + nft present.
#
# Usage: qemu-login-test.sh <Image> <rootfs.ext4> [timeout]
# Drives qemu-system-aarch64 -M virt with a serial console, logs in as root,
# runs the checks, prints results.

set -u
KERNEL="${1:?Image}"
ROOTFS="${2:?rootfs}"
TIMEOUT="${3:-90}"
WORK="$(mktemp -d)"
LOG="$WORK/serial.log"
QEMU="$(command -v qemu-system-aarch64 || echo /opt/homebrew/bin/qemu-system-aarch64)"

# Start QEMU with a FIFO for input so we can type at the login prompt.
IN="$WORK/in.fifo"
mkfifo "$IN"
"$QEMU" -M virt -cpu cortex-a53 -m 1G -smp 2 \
    -kernel "$KERNEL" \
    -append "root=/dev/vda rootwait console=ttyAMA0 panic=-1" \
    -drive "file=$ROOTFS,if=none,format=raw,id=hd0" -device virtio-blk-device,drive=hd0 \
    -netdev user,id=eth0 -device virtio-net-device,netdev=eth0 \
    -nographic -no-reboot -serial stdio >"$LOG" 2>&1 <"$IN" &
QPID=$!
exec 9>"$IN"   # keep FIFO writer open

# Wait for login prompt, then log in and run checks.
{
    for i in $(seq 1 200); do
        grep -q "login:" "$LOG" 2>/dev/null && break
        sleep 0.5
    done
    sleep 1
    echo "root"
    sleep 1
    # Banner: run each command, capture output via marker
    for cmd in \
        "uname -m" \
        "id -u" \
        "systemctl is-active balansir-daemon balansir-executor" \
        "ls -la /run/balansir" \
        "balansir-cli status" \
        "balansir-cli fingerprint" \
        "balansir-cli desired" \
        "nft --version" \
        "exit"; do
        echo "###CMD### $cmd"
        echo "$cmd"
        sleep 2
    done
} >&9 &
DRIVER=$!

# Wait for the driver to finish (or timeout).
gtimeout "$TIMEOUT" wait "$DRIVER" 2>/dev/null || true
sleep 3
exec 9>&-
kill "$QPID" 2>/dev/null; wait "$QPID" 2>/dev/null

echo "============================================================"
echo "FULL-STACK RESULT"
# Extract command outputs between markers
python3 - "$LOG" <<'PY'
import re,sys
log=open(sys.argv[1]).read()
# Split by marker; the first line after each marker is the command echo,
# subsequent lines until the next marker are output.
parts=log.split("###CMD### ")
for p in parts[1:]:
    lines=p.splitlines()
    cmd=lines[0]
    out="\n".join(lines[1:]).strip()
    # Trim prompt noise
    out=re.sub(r'#\s*$','',out).strip()
    print(f"$ {cmd}\n{out}\n---")
PY
echo "============================================================"
