#!/bin/sh
# BalanSir post-build: enable services, serial console, systemd bits.
#
# Runs inside Buildroot after the rootfs is assembled (TARGET_DIR).

set -eu

TARGET_DIR="${1}"

# --- BalanSir services ------------------------------------------------------
# Enable the daemon + executor so the box enforces policy after first boot
# (mission: image must start networking -> executor -> daemon -> config ->
# first reconcile automatically).
if [ -d "${TARGET_DIR}/etc/systemd/system" ]; then
    mkdir -p "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants"
    ln -sf /etc/systemd/system/balansir-daemon.service \
        "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/balansir-daemon.service"
    ln -sf /etc/systemd/system/balansir-executor.service \
        "${TARGET_DIR}/etc/systemd/system/multi-user.target.wants/balansir-executor.service"
fi

# --- Serial console (recovery) ----------------------------------------------
if [ -e "${TARGET_DIR}/etc/inittab" ]; then
    grep -qE '^tty1::' "${TARGET_DIR}/etc/inittab" || \
        sed -i '/GENERIC_SERIAL/a\
tty1::respawn:/sbin/getty -L tty1 0 vt100 # HDMI console' "${TARGET_DIR}/etc/inittab"
elif [ -d "${TARGET_DIR}/etc/systemd" ]; then
    mkdir -p "${TARGET_DIR}/etc/systemd/system/getty.target.wants"
    ln -sf /lib/systemd/system/getty@.service \
        "${TARGET_DIR}/etc/systemd/system/getty.target.wants/getty@tty1.service"
    # Serial getty on ttyAMA0 (QEMU virt console / RPi UART). The drop-in in
    # the rootfs overlay autologs root for the dev/QEMU image.
    ln -sf /lib/systemd/system/serial-getty@.service \
        "${TARGET_DIR}/etc/systemd/system/getty.target.wants/serial-getty@ttyAMA0.service"
fi

# --- balansir unprivileged daemon user --------------------------------------
# The daemon runs as UID 1500 (balansir); the executor accepts it via
# BALANSIR_ALLOWED_UIDS=0,1500 (ADR-030). Create the account + state dir.
if ! grep -q '^balansir:' "${TARGET_DIR}/etc/passwd" 2>/dev/null; then
    echo 'balansir:x:1500:1500:BalanSir daemon:/var/lib/balansir:/sbin/nologin' >> \
        "${TARGET_DIR}/etc/passwd"
    echo 'balansir:x:1500:' >> "${TARGET_DIR}/etc/group"
fi
mkdir -p "${TARGET_DIR}/var/lib/balansir"
