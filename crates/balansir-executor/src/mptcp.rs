//! MPTCP backend (`MsgType::MptcpOp`).
//!
//! The executor is the only component that touches the kernel MPTCP stack:
//! `net.mptcp.enabled` sysctl and `ip mptcp endpoint add/del` (iproute2's
//! netlink wrapper). Linux kernels ≥ 5.6 ship native MPTCP; the kernel handles
//! subflow setup, aggregation and failover once paths are configured. The
//! daemon's MPTCP manager observes `/proc/net/mptcp` for health/failover.
//!
//! Security: fixed command shapes, validated addresses (IP literals only), no
//! shell.

use async_trait::async_trait;
use balansir_common::network::{MptcpEndpoint, MptcpResult, MptcpSubflow};
use balansir_common::{Error, Result};

const MPTCP_ENABLED_SYSCTL: &str = "/proc/sys/net/mptcp/enabled";

/// Validate an IP literal (IPv4 or IPv6). Hostnames are rejected — an MPTCP
/// endpoint must be an address the local host owns.
fn valid_ip(input: &str) -> bool {
    input.parse::<std::net::IpAddr>().is_ok()
}

fn valid_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| Error::Fatal(format!("{cmd}: {e}")))?;
    if !out.status.success() {
        return Err(Error::Fatal(format!(
            "{cmd} {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Whether the running kernel has MPTCP support compiled in.
fn kernel_has_mptcp() -> bool {
    std::path::Path::new(MPTCP_ENABLED_SYSCTL).exists()
}

fn enabled_state() -> Option<bool> {
    std::fs::read_to_string(MPTCP_ENABLED_SYSCTL)
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .map(|v| v == 1)
}

/// Parse `ip mptcp endpoint show` output into endpoints.
fn parse_endpoints(out: &str) -> Vec<MptcpEndpoint> {
    let mut endpoints = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(addr) = fields.next() else {
            continue;
        };
        if addr == "subflow" || addr == "signal" {
            continue; // header continuation
        }
        let mut ep = MptcpEndpoint {
            address: addr.to_string(),
            ..Default::default()
        };
        let mut rest: Vec<&str> = fields.collect();
        while let Some(f) = rest.first() {
            match *f {
                "dev" => {
                    if rest.len() >= 2 {
                        ep.iface = rest[1].to_string();
                        rest = rest[2..].to_vec();
                    } else {
                        break;
                    }
                }
                "id" => {
                    if rest.len() >= 2 {
                        ep.local_id = rest[1].parse().unwrap_or(0);
                        rest = rest[2..].to_vec();
                    } else {
                        break;
                    }
                }
                _ => {
                    if matches!(*f, "subflow" | "signal" | "backup" | "fullmesh") {
                        ep.flags.push((*f).to_string());
                    }
                    rest = rest[1..].to_vec();
                }
            }
        }
        endpoints.push(ep);
    }
    endpoints
}

/// Parse `/proc/net/mptcp` subflow lines.
///
/// Format (kernel 5.6+): one data line per subflow, continuation lines follow.
/// We only need the first three fields (index, local, remote) plus state words.
fn parse_subflows(out: &str) -> Vec<MptcpSubflow> {
    let mut subflows = Vec::new();
    for line in out.lines() {
        if let Some(s) = parse_subflow_line(line) {
            subflows.push(s);
        }
    }
    subflows
}

fn parse_subflow_line(line: &str) -> Option<MptcpSubflow> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.contains("local_address") {
        return None;
    }
    let mut fields = trimmed.split_whitespace();
    // index: 1:
    let idx = fields.next()?.trim_end_matches(':');
    let _ = idx.parse::<u32>().ok()?;
    let local = fields.next()?.to_string();
    let remote = fields.next()?.to_string();
    let mut sub = MptcpSubflow {
        local,
        remote,
        ..Default::default()
    };
    if trimmed.contains("ESTABLISHED") {
        sub.state = "ESTABLISHED".to_string();
    }
    if trimmed.contains("SYN-SENT") {
        sub.state = "SYN-SENT".to_string();
    }
    if trimmed.contains("BACKUP") || trimmed.contains("backup") {
        sub.backup = true;
    }
    Some(sub)
}

/// The privileged MPTCP mechanism.
#[async_trait]
pub trait MptcpBackend: Send + Sync {
    async fn set_enabled(&self, enabled: bool) -> Result<MptcpResult>;
    async fn add_endpoint(&self, address: &str, interface: &str) -> Result<MptcpResult>;
    async fn remove_endpoint(&self, address: &str) -> Result<MptcpResult>;
    async fn status(&self) -> Result<MptcpResult>;
}

/// Real sysctl + iproute2 implementation.
pub struct IpTcpBackend;

#[async_trait]
impl MptcpBackend for IpTcpBackend {
    async fn set_enabled(&self, enabled: bool) -> Result<MptcpResult> {
        if !kernel_has_mptcp() {
            return Err(Error::Misconfiguration(
                "mptcp: kernel has no MPTCP support (CONFIG_MPTCP missing or kernel < 5.6)".into(),
            ));
        }
        std::fs::write(MPTCP_ENABLED_SYSCTL, if enabled { "1\n" } else { "0\n" })
            .map_err(|e| Error::Fatal(format!("mptcp: write {MPTCP_ENABLED_SYSCTL}: {e}")))?;
        let detail = if enabled {
            "MPTCP stack enabled".to_string()
        } else {
            "MPTCP stack disabled".to_string()
        };
        Ok(MptcpResult {
            ok: true,
            detail,
            enabled: enabled_state(),
            endpoints: Vec::new(),
            subflows: Vec::new(),
        })
    }

    async fn add_endpoint(&self, address: &str, interface: &str) -> Result<MptcpResult> {
        if !kernel_has_mptcp() {
            return Err(Error::Misconfiguration(
                "mptcp: kernel has no MPTCP support (CONFIG_MPTCP missing or kernel < 5.6)".into(),
            ));
        }
        if !valid_ip(address) {
            return Err(Error::Misconfiguration(format!(
                "mptcp: invalid endpoint address {address}"
            )));
        }
        if !interface.is_empty() && !valid_iface(interface) {
            return Err(Error::Misconfiguration(
                "mptcp: invalid interface name".into(),
            ));
        }
        let mut args = vec!["mptcp", "endpoint", "add", address];
        if !interface.is_empty() {
            args.push("dev");
            args.push(interface);
        }
        args.push("signal");
        run("ip", &args)?;
        Ok(MptcpResult {
            ok: true,
            detail: format!("endpoint {address} added"),
            enabled: enabled_state(),
            endpoints: Vec::new(),
            subflows: Vec::new(),
        })
    }

    async fn remove_endpoint(&self, address: &str) -> Result<MptcpResult> {
        if !kernel_has_mptcp() {
            return Err(Error::Misconfiguration(
                "mptcp: kernel has no MPTCP support (CONFIG_MPTCP missing or kernel < 5.6)".into(),
            ));
        }
        if !valid_ip(address) {
            return Err(Error::Misconfiguration(format!(
                "mptcp: invalid endpoint address {address}"
            )));
        }
        run("ip", &["mptcp", "endpoint", "delete", address])?;
        Ok(MptcpResult {
            ok: true,
            detail: format!("endpoint {address} removed"),
            enabled: enabled_state(),
            endpoints: Vec::new(),
            subflows: Vec::new(),
        })
    }

    async fn status(&self) -> Result<MptcpResult> {
        let enabled = enabled_state();
        if enabled.is_none() {
            return Err(Error::Misconfiguration(
                "mptcp: kernel has no MPTCP support (CONFIG_MPTCP missing or kernel < 5.6)".into(),
            ));
        }
        let mut result = MptcpResult {
            ok: true,
            detail: "mptcp status".to_string(),
            enabled,
            endpoints: Vec::new(),
            subflows: Vec::new(),
        };
        if let Ok(out) = run("ip", &["mptcp", "endpoint", "show"]) {
            result.endpoints = parse_endpoints(&out);
        }
        if let Ok(out) = std::fs::read_to_string("/proc/net/mptcp") {
            result.subflows = parse_subflows(&out);
        }
        result.detail = format!(
            "enabled={} endpoints={} subflows={}",
            result
                .enabled
                .map(|b| b.to_string())
                .unwrap_or_else(|| "?".into()),
            result.endpoints.len(),
            result.subflows.len()
        );
        Ok(result)
    }
}

/// Record-only backend used when no privileged MPTCP mechanism is available.
/// Reports sysctl state and `/proc/net/mptcp` (read-only), refuses mutations.
pub struct ReadOnlyMptcpBackend;

#[async_trait]
impl MptcpBackend for ReadOnlyMptcpBackend {
    async fn set_enabled(&self, _enabled: bool) -> Result<MptcpResult> {
        Err(Error::Misconfiguration(
            "mptcp: state changes require the privileged backend".into(),
        ))
    }
    async fn add_endpoint(&self, _a: &str, _i: &str) -> Result<MptcpResult> {
        Err(Error::Misconfiguration(
            "mptcp: endpoint changes require the privileged backend".into(),
        ))
    }
    async fn remove_endpoint(&self, _a: &str) -> Result<MptcpResult> {
        Err(Error::Misconfiguration(
            "mptcp: endpoint changes require the privileged backend".into(),
        ))
    }
    async fn status(&self) -> Result<MptcpResult> {
        let enabled = enabled_state();
        let mut result = MptcpResult {
            ok: true,
            detail: "mptcp status (read-only)".to_string(),
            enabled,
            endpoints: Vec::new(),
            subflows: Vec::new(),
        };
        if let Ok(out) = std::fs::read_to_string("/proc/net/mptcp") {
            result.subflows = parse_subflows(&out);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_validation() {
        assert!(valid_ip("10.0.0.1"));
        assert!(valid_ip("2001:db8::1"));
        assert!(valid_ip("::1"));
        assert!(!valid_ip("example.com"));
        assert!(!valid_ip("10.0.0.1/24"));
        assert!(!valid_ip(""));
    }

    #[test]
    fn parses_endpoint_show() {
        let out = "10.0.0.1 subflow signal dev eth0 id 1\n2001:db8::1 signal id 2\n";
        let eps = parse_endpoints(out);
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].address, "10.0.0.1");
        assert_eq!(eps[0].iface, "eth0");
        assert_eq!(eps[0].local_id, 1);
        assert_eq!(eps[0].flags, vec!["subflow", "signal"]);
        assert_eq!(eps[1].address, "2001:db8::1");
        assert_eq!(eps[1].local_id, 2);
    }

    #[test]
    fn parses_proc_net_mptcp() {
        // A realistic /proc/net/mptcp snippet (first data line only; we only
        // need local/remote + state words).
        let out = "\
1: 10.0.0.2:12345 10.0.0.1:443 ESTABLISHED 0x00000001 0x00000000 0x00000000 0x00000000
    token remid locid
2: 10.0.0.2:23456 10.0.0.1:443 SYN-SENT 0x00000001 0x00000000 0x00000000 0x00000000
    token remid locid
";
        let subs = parse_subflows(out);
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].local, "10.0.0.2:12345");
        assert_eq!(subs[0].remote, "10.0.0.1:443");
        assert_eq!(subs[0].state, "ESTABLISHED");
        assert_eq!(subs[1].state, "SYN-SENT");
    }
}
