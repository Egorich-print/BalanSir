#!/bin/bash
# BalanSir RK68 (RK3568) post-build hook.
#
# Enables the BalanSir systemd units and serial getty in the target rootfs so
# a fresh NFS/TFTP root boots into the policy engine immediately.
set -e

TARGET_DIR="${TARGET_DIR:-$1}"
if [ -z "${TARGET_DIR}" ]; then
    echo "Usage: $0 <target-dir>" >&2
    exit 1
fi

# Enable BalanSir units.
for unit in balansir-daemon.service balansir-executor.service; do
    if [ -f "${TARGET_DIR}/etc/systemd/system/${unit}" ]; then
        ln -sf "/etc/systemd/system/${unit}" \
            "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/${unit}"
    fi
done

# Serial console on ttyS0 for recovery + boot logs (board-info §UART).
if [ -d "${TARGET_DIR}/etc/systemd/system" ]; then
    mkdir -p "${TARGET_DIR}/etc/systemd/system/serial-getty@ttyS0.service.d"
    cat > "${TARGET_DIR}/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty -a root --noclear -s ttyS0 115200,57600,38400,9600
EOF
fi

# BalanSir user (UID 1500, ADR-030).
if ! grep -q "^balansir:" "${TARGET_DIR}/etc/passwd"; then
    echo "balansir:x:1500:1500:balansir:/var/lib/balansir:/bin/sh" >> "${TARGET_DIR}/etc/passwd"
    echo "balansir:x:1500:" >> "${TARGET_DIR}/etc/group"
fi

# Persistent state dirs.
mkdir -p "${TARGET_DIR}/var/lib/balansir" "${TARGET_DIR}/var/log/balansir"
