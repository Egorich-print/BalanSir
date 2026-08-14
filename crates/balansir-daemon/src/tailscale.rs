//! Tailscale integration (WebUI-driven remote access).
//!
//! Orchestration/control lives in Rust; the `tailscale`/`tailscaled` binaries
//! are the upstream runtime. We talk to them via their CLI (status JSON,
//! up/down) — no shell interpolation, no arbitrary user commands. Secrets are
//! never stored; authentication uses the interactive `tailscale up` flow.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;

/// Location of the `tailscale` CLI.
pub fn tailscale_bin() -> PathBuf {
    balansir_common::paths::resolve_bin_or_default("tailscale")
}

/// Tailscale node status (subset of `tailscale status --json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TailscaleStatus {
    pub installed: bool,
    pub backend_state: String,
    pub self_ip: Option<String>,
    pub self_dns: Option<String>,
    pub hostname: Option<String>,
    pub peers: usize,
    pub version: Option<String>,
    pub error: Option<String>,
}

/// Probe Tailscale status by running `tailscale status --json`.
pub async fn status() -> TailscaleStatus {
    let bin = tailscale_bin();
    if !bin.is_file() {
        return TailscaleStatus {
            installed: false,
            error: Some("tailscale binary not found".into()),
            ..Default::default()
        };
    }

    let output = Command::new(&bin).args(["status", "--json"]).output();

    let Ok(out) = output else {
        return TailscaleStatus {
            installed: true,
            error: Some("failed to run tailscale status".into()),
            ..Default::default()
        };
    };

    if !out.status.success() {
        // Exit non-zero usually means "logged out" or daemon down.
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        return TailscaleStatus {
            installed: true,
            error: Some(if stderr.is_empty() {
                "not authenticated or tailscaled not running".into()
            } else {
                stderr
            }),
            ..Default::default()
        };
    }

    parse_status_json(&out.stdout)
}

fn parse_status_json(bytes: &[u8]) -> TailscaleStatus {
    #[derive(Deserialize)]
    struct Status {
        #[serde(rename = "BackendState")]
        backend_state: Option<String>,
        #[serde(rename = "Self")]
        self_node: Option<SelfNode>,
        #[serde(rename = "Peer")]
        peer: Option<serde_json::Map<String, serde_json::Value>>,
        #[serde(rename = "Version")]
        version: Option<String>,
    }
    #[derive(Deserialize)]
    struct SelfNode {
        #[serde(rename = "TailscaleIPs")]
        tailscale_ips: Option<Vec<String>>,
        #[serde(rename = "DNSName")]
        dns_name: Option<String>,
        #[serde(rename = "HostName")]
        host_name: Option<String>,
    }

    let Ok(status) = serde_json::from_slice::<Status>(bytes) else {
        return TailscaleStatus {
            installed: true,
            error: Some("malformed tailscale status".into()),
            ..Default::default()
        };
    };

    TailscaleStatus {
        installed: true,
        backend_state: status.backend_state.unwrap_or_default(),
        self_ip: status
            .self_node
            .as_ref()
            .and_then(|s| s.tailscale_ips.clone())
            .and_then(|ips| ips.first().cloned()),
        self_dns: status.self_node.as_ref().and_then(|s| s.dns_name.clone()),
        hostname: status.self_node.as_ref().and_then(|s| s.host_name.clone()),
        peers: status.peer.as_ref().map(|p| p.len()).unwrap_or(0),
        version: status.version,
        error: None,
    }
}

/// Bring Tailscale up (authenticate/interactive flow). Returns an error string
/// on failure; the caller surfaces a login flow to the user.
pub async fn up() -> Result<(), String> {
    let bin = tailscale_bin();
    let out = Command::new(&bin)
        .args(["up"])
        .output()
        .map_err(|e| format!("failed to run tailscale up: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// Bring Tailscale down.
pub async fn down() -> Result<(), String> {
    let bin = tailscale_bin();
    let out = Command::new(&bin)
        .args(["down"])
        .output()
        .map_err(|e| format!("failed to run tailscale down: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_status_json() {
        let json = r#"{
            "BackendState": "Running",
            "Version": "1.78.1",
            "Self": {
                "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
                "DNSName": "node.tailnet.ts.net.",
                "HostName": "node"
            },
            "Peer": {"100.64.0.2": {"HostName": "other"}}
        }"#;
        let s = parse_status_json(json.as_bytes());
        assert!(s.installed);
        assert_eq!(s.backend_state, "Running");
        assert_eq!(s.self_ip.as_deref(), Some("100.64.0.1"));
        assert_eq!(s.peers, 1);
        assert_eq!(s.version.as_deref(), Some("1.78.1"));
        assert!(s.error.is_none());
    }

    #[test]
    fn logged_out_status_has_error() {
        // tailscale status --json exits non-zero when logged out; the CLI
        // wrapper maps that to an error string before parsing.
        let s = TailscaleStatus {
            installed: true,
            backend_state: String::new(),
            self_ip: None,
            self_dns: None,
            hostname: None,
            peers: 0,
            version: None,
            error: Some("not authenticated".into()),
        };
        assert!(s.error.is_some());
    }
}
