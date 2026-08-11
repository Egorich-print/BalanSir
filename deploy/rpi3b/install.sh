#!/bin/sh
# Deploy BalanSir to a Raspberry Pi 3B+ (or any arm64 Linux) over SSH.
#
# Usage:  deploy/rpi3b/install.sh [user@]host
#
# Expects the static aarch64 binaries already built (build-aarch64.sh). Copies:
#   - binaries to /usr/local/bin
#   - systemd units to /etc/systemd/system
#   - example config to /etc/balansir/balansir.toml (if absent)
# then enables balansir-daemon.service + balansir-executor.service and starts
# them. The daemon loads the config at boot via BALANSIR_CONFIG (P7.2.1).

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 [user@]host" >&2
    echo "e.g.:  $0 pi@192.168.1.50" >&2
    exit 1
fi
HOST="$1"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${ROOT}/target/aarch64-unknown-linux-musl/release"

for b in balansir-daemon balansir-executor balansir-cli; do
    [ -x "${OUT}/${b}" ] || {
        echo "error: ${OUT}/${b} missing; run deploy/rpi3b/build-aarch64.sh first" >&2
        exit 1
    }
done

echo ">> copying binaries to ${HOST}"
scp "${OUT}/balansir-daemon" "${OUT}/balansir-executor" "${OUT}/balansir-cli" \
    "${HOST}:/tmp/"

echo ">> installing binaries + units + config"
ssh "${HOST}" '
    set -euo pipefail
    install -m 0755 /tmp/balansir-daemon /tmp/balansir-executor /tmp/balansir-cli /usr/local/bin/
    rm -f /tmp/balansir-daemon /tmp/balansir-executor /tmp/balansir-cli

    install -d /etc/balansir /run/balansir

    # Runtime dir ownership for the split daemon/executor UIDs (ADR-030):
    # systemd-tmpfiles creates /run/balansir as root:balansir before services.
    install -d /usr/lib/tmpfiles.d
    install -m 0644 /dev/stdin /usr/lib/tmpfiles.d/balansir.conf <<'TMPFILES'
d /run/balansir 0775 root balansir -
TMPFILES

    # Unprivileged daemon account (fixed, ADR-030): the daemon unit runs as
    # UID 1500 (balansir); the executor accepts it via BALANSIR_ALLOWED_UIDS.
    if ! id -u balansir >/dev/null 2>&1; then
        useradd --system --uid 1500 --home-dir /var/lib/balansir \
            --shell /usr/sbin/nologin balansir
    fi
    install -d -o balansir -g balansir /var/lib/balansir

    # systemd units (daemon carries BALANSIR_CONFIG; executor is the
    # privileged nft mechanism). Type=simple: neither binary implements
    # sd_notify (fixed, ADR-030).
    install -m 0644 /dev/stdin /etc/systemd/system/balansir-daemon.service <<UNIT
[Unit]
Description=BalanSir Network Policy Engine - Daemon
After=network.target balansir-executor.service
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/balansir-daemon
Environment=BALANSIR_CONFIG=/etc/balansir/balansir.toml
Environment=BALANSIR_ALLOWED_UIDS=0,1500
User=balansir
Group=balansir
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

    install -m 0644 /dev/stdin /etc/systemd/system/balansir-executor.service <<UNIT
[Unit]
Description=BalanSir Network Policy Engine - Executor (privileged)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/balansir-executor
Environment=BALANSIR_ALLOWED_UIDS=0,1500
Restart=on-failure
RestartSec=5
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
UNIT

    # Do not overwrite an existing operator config.
    if [ ! -f /etc/balansir/balansir.toml ]; then
        echo "[[rules]]
id = 1
action = \"block\"
priority = 100

[policy]
empty_config_action = \"pass\"
" > /etc/balansir/balansir.toml
    fi

    systemctl daemon-reload
    systemctl enable balansir-executor.service balansir-daemon.service
    systemctl restart balansir-executor.service balansir-daemon.service
'

echo ">> done"
echo "   status:   ssh ${HOST} systemctl status balansir-daemon"
echo "   policy:   ssh ${HOST} balansir-cli status"
echo "   reload:   ssh ${HOST} balansir-cli reload /etc/balansir/balansir.toml"
