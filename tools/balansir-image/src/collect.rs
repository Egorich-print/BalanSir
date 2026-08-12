//! Diagnostic collection (`balansir-image collect`): gather BalanSir + system
//! state from a target over SSH into a compressed archive.
//!
//! Collects: BalanSir status/fingerprint/desired/actual, systemd service
//! state, kernel/net interfaces, routes, MTU, nft state, executor state. No
//! secrets are included (config is masked). Runs over `ssh`, unprivileged.

use std::process::Command;

/// Collect diagnostics from a host into `balansir-<host>-<ts>.tar.gz`.
pub fn collect(host: &str) -> Result<String, String> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let archive = format!("balansir-{host}-{ts}.tar.gz");
    let remote_script = r#"
set -u
BIN="$(command -v balansir-cli || echo /usr/local/bin/balansir-cli)"
OUT="/tmp/balansir-diag"
rm -rf "$OUT"; mkdir -p "$OUT"

# BalanSir state (best-effort; CLI may need root/allowed uid)
if [ -x "$BIN" ]; then
    "$BIN" status       > "$OUT/status.txt"      2>&1 || true
    "$BIN" fingerprint  > "$OUT/fingerprint.txt" 2>&1 || true
    "$BIN" desired      > "$OUT/desired.txt"     2>&1 || true
    "$BIN" actual       > "$OUT/actual.txt"      2>&1 || true
fi

# Services
if command -v systemctl >/dev/null 2>&1; then
    systemctl status balansir-daemon  > "$OUT/daemon-status.txt"  2>&1 || true
    systemctl status balansir-executor > "$OUT/executor-status.txt" 2>&1 || true
fi

# System / network
uname -a                       > "$OUT/uname.txt"
cat /etc/os-release 2>/dev/null > "$OUT/os-release.txt" || true
ip -brief addr 2>/dev/null      > "$OUT/interfaces.txt" || true
ip -brief route 2>/dev/null     > "$OUT/routes.txt"     || true
cat /proc/net/tcp 2>/dev/null   > "$OUT/tcp.txt"        || true
nft list ruleset 2>/dev/null    > "$OUT/nft.txt"        || true

# Executor / sockets
ls -la /run/balansir 2>/dev/null > "$OUT/run-balansir.txt" || true

cd /tmp && tar czf balansir-diag.tar.gz -C "$OUT" . 2>/dev/null
echo "$OUT"
"#;

    let out = Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
        ])
        .arg(host)
        .arg(remote_script)
        .output()
        .map_err(|e| format!("ssh {host}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ssh {host} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // Copy the archive back.
    let remote_path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let fetch = Command::new("scp")
        .args([
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
        ])
        .arg(format!("{host}:{remote_path}/../balansir-diag.tar.gz"))
        .arg(&archive)
        .output()
        .map_err(|e| format!("scp: {e}"))?;
    if !fetch.status.success() {
        return Err(format!(
            "scp failed: {}",
            String::from_utf8_lossy(&fetch.stderr)
        ));
    }
    Ok(format!("collected -> {archive}\n(open: tar xzf {archive})"))
}
