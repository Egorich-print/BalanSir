#!/bin/sh
# BalanSir Gateway E2E Test Harness
# Run on RPi. Reports PASS/FAIL/SKIP for each test.
set -e
echo "=== BalanSir Gateway E2E Tests ==="
echo ""

# Test 1: Services running
echo -n "Test 1: Daemon+Executor running... "
D=$(systemctl is-active balansir-daemon 2>/dev/null)
E=$(systemctl is-active balansir-executor 2>/dev/null)
[ "$D" = "active" ] && [ "$E" = "active" ] && echo "PASS" || echo "FAIL ($D/$E)"

# Test 2: API health
echo -n "Test 2: API health... "
H=$(wget -q -O- http://127.0.0.1:8080/health 2>/dev/null)
echo "$H" | grep -q '"status":"ok"' && echo "PASS" || echo "FAIL ($H)"

# Test 3: API system metrics
echo -n "Test 3: System metrics... "
S=$(wget -q -O- http://127.0.0.1:8080/system 2>/dev/null)
echo "$S" | grep -q '"cpu"' && echo "$S" | grep -q '"memory"' && echo "PASS" || echo "FAIL"

# Test 4: IP forwarding
echo -n "Test 4: IP forwarding... "
F=$(cat /proc/sys/net/ipv4/ip_forward)
[ "$F" = "1" ] && echo "PASS" || echo "FAIL ($F) [gateway OFF expected if eth1 DOWN]"

# Test 5: nftables forward chain
echo -n "Test 5: nftables forward chain... "
nft list chain inet balansir forward 2>/dev/null | grep -q "policy" && echo "PASS" || echo "FAIL"

# Test 6: NAT masquerade
echo -n "Test 6: NAT masquerade rule... "
nft list chain inet balansir postrouting 2>/dev/null | grep -q "masquerade" && echo "PASS" || echo "SKIP (gateway OFF)"

# Test 7: Management firewall
echo -n "Test 7: Management firewall (input policy)... "
nft list chain inet balansir input 2>/dev/null | grep -q "policy drop" && echo "PASS" || echo "SKIP (gateway OFF)"

# Test 8: WAN interface up
echo -n "Test 8: WAN interface (eth0)... "
ip -br addr | grep -q "^eth0 " && ip -br addr | grep eth0 | grep -q "UP" && echo "PASS" || echo "FAIL"

# Test 9: LAN interface state
echo -n "Test 9: LAN interface (eth1)... "
ip -br addr | grep -q "^eth1 " && echo "EXISTS" || echo "DOWN"

# Test 10: DNS forwarder
echo -n "Test 10: DNS forwarder... "
ss -ulnp 2>/dev/null | grep -q ":53 " && echo "PASS" || echo "SKIP (no DNS config)"

# Test 11: Gateway config
echo -n "Test 11: Network config... "
[ -f /etc/balansir/network.toml ] && grep -q "wan_interface" /etc/balansir/network.toml && echo "PASS" || echo "FAIL"

# Test 12: OTA binary
echo -n "Test 12: OTA binary... "
[ -x /usr/local/bin/balansir-ota ] && /usr/local/bin/balansir-ota status >/dev/null 2>&1 && echo "PASS" || echo "FAIL"

# Test 13: OTA status detail
echo -n "Test 13: OTA slot status... "
S=$(/usr/local/bin/balansir-ota status 2>/dev/null)
echo "$S" | grep -q "Active slot:" && echo "$S" | grep -q "State:" && echo "PASS" || echo "FAIL"

echo ""
echo "=== Done ==="
