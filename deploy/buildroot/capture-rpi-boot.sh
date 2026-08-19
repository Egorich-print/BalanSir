#!/usr/bin/env bash
# Capture the Raspberry Pi boot log over UART until Ctrl-C / kill.
#
# Usage: capture-rpi-boot.sh [port] [outfile]
#   default port = /dev/cu.usbserial-A5069RR4
#   default out  = /Users/egorich/ai-workstation/BalanSir-mission/rpi-boot.log
#
# Writes raw bytes to the log. Timestamps are added via `ts` if available.
set -u
PORT="${1:-/dev/cu.usbserial-A5069RR4}"
OUT="${2:-/Users/egorich/ai-workstation/BalanSir-mission/rpi-boot.log}"

echo ">> listening on $PORT -> $OUT (Ctrl-C to stop)"
exec 3<>"$PORT" || { echo "error: cannot open $PORT (is screen holding it?)"; exit 1; }
if command -v ts >/dev/null 2>&1; then
    cat <&3 | ts '[%Y-%m-%d %H:%M:%S]' > "$OUT"
else
    cat <&3 > "$OUT"
fi
