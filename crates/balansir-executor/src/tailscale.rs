//! Tailscale driver (executor side).
//!
//! BalanSir orchestrates Tailscale but does not reimplement it: the upstream
//! `tailscale` binary is the runtime. All orchestration lives in Rust, all
//! privileged invocations go through the executor's allowlisted `TailscaleOp`
//! boundary, and every command-line argument is strictly validated before any
//! process is spawned (no shell, no free-form flags).
//!
//! Secrets (auth keys) are passed to the binary on stdin-free argv of a
//! short-lived child process and are never stored or logged.

use async_trait::async_trait;
use balansir_common::network::{TailscalePeer, TailscaleResult, TailscaleStatus};
use std::collections::HashMap;
use std::process::Command;
use std::time::SystemTime;

/// Resolve the `tailscale` binary from standard locations.
fn tailscale_bin() -> Option<std::path::PathBuf> {
    balansir_common::paths::resolve_bin("tailscale")
}

/// Validate a subnet CIDR route argument (`10.0.0.0/24` or `2001:db8::/32`).
fn validate_route(route: &str) -> bool {
    let Some((addr, prefix)) = route.split_once('/') else {
        return false;
    };
    let Ok(prefix): Result<u8, _> = prefix.parse() else {
        return false;
    };
    let ip: std::net::IpAddr = match addr.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    match ip {
        std::net::IpAddr::V4(v4) => prefix <= 32 && !v4.is_unspecified(),
        std::net::IpAddr::V6(v6) => prefix <= 128 && !v6.is_unspecified(),
    }
}

/// The Tailscale privileged driver.
#[async_trait]
pub trait TailscaleDriver: Send + Sync {
    async fn status(&self) -> TailscaleStatus;
    async fn up(&self, auth_key: Option<&str>) -> TailscaleResult;
    async fn down(&self) -> TailscaleResult;
    async fn reconnect(&self) -> TailscaleResult;
    async fn set_routes(&self, routes: &[String], exit_node: bool) -> TailscaleResult;
}

/// Driver that shells out to the upstream `tailscale` binary.
pub struct CliTailscaleDriver {
    binary: std::path::PathBuf,
}

impl CliTailscaleDriver {
    pub fn new() -> Result<Self, String> {
        tailscale_bin()
            .map(|binary| Self { binary })
            .ok_or_else(|| "tailscale binary not found".to_string())
    }

    fn run(&self, args: &[&str]) -> std::io::Result<std::process::Output> {
        Command::new(&self.binary)
            .args(args)
            .output()
    }

    fn run_stdin(&self, args: &[&str], stdin: &str) -> std::io::Result<std::process::Output> {
        use std::io::Write;
        let mut child = Command::new(&self.binary)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(stdin.as_bytes());
        }
        child.wait_with_output()
    }
}

#[async_trait]
impl TailscaleDriver for CliTailscaleDriver {
    async fn status(&self) -> TailscaleStatus {
        let output = match self.run(&["status", "--json"]) {
            Ok(out) if out.status.success() => out,
            Ok(out) => {
                return TailscaleStatus {
                    installed: true,
                    backend_state: "Error".into(),
                    summary: format!(
                        "tailscale status failed: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                    ..Default::default()
                }
            }
            Err(e) => {
                return TailscaleStatus {
                    installed: true,
                    backend_state: "Unavailable".into(),
                    summary: format!("tailscale status failed: {e}"),
                    ..Default::default()
                }
            }
        };
        parse_status(&output.stdout)
    }

    async fn up(&self, auth_key: Option<&str>) -> TailscaleResult {
        let mut args = vec!["up"];
        let mut stdin = String::new();
        if let Some(key) = auth_key {
            if key.is_empty() || key.len() > 512 || !key.chars().all(|c| c.is_ascii() && !c.is_control()) {
                return TailscaleResult {
                    ok: false,
                    detail: "invalid auth key".into(),
                };
            }
            stdin = format!("{key}\n");
            args.push("--auth-key");
            args.push("-");
        }
        let output = if stdin.is_empty() {
            self.run(&args)
        } else {
            self.run_stdin(&args, &stdin)
        };
        match output {
            Ok(out) if out.status.success() => TailscaleResult {
                ok: true,
                detail: "tailscale up".into(),
            },
            Ok(out) => TailscaleResult {
                ok: false,
                detail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            },
            Err(e) => TailscaleResult {
                ok: false,
                detail: format!("tailscale up failed: {e}"),
            },
        }
    }

    async fn down(&self) -> TailscaleResult {
        match self.run(&["down"]) {
            Ok(out) if out.status.success() => TailscaleResult {
                ok: true,
                detail: "tailscale down".into(),
            },
            Ok(out) => TailscaleResult {
                ok: false,
                detail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            },
            Err(e) => TailscaleResult {
                ok: false,
                detail: format!("tailscale down failed: {e}"),
            },
        }
    }

    async fn reconnect(&self) -> TailscaleResult {
        match self.run(&["reconnect"]) {
            Ok(out) if out.status.success() => TailscaleResult {
                ok: true,
                detail: "tailscale reconnect".into(),
            },
            Ok(out) => TailscaleResult {
                ok: false,
                detail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            },
            Err(e) => TailscaleResult {
                ok: false,
                detail: format!("tailscale reconnect failed: {e}"),
            },
        }
    }

    async fn set_routes(&self, routes: &[String], exit_node: bool) -> TailscaleResult {
        if routes.iter().any(|r| !validate_route(r)) {
            return TailscaleResult {
                ok: false,
                detail: "invalid subnet route (expected CIDR like 10.0.0.0/24)".into(),
            };
        }
        let mut args = vec!["up"];
        for route in routes {
            args.push("--advertise-routes");
            args.push(route);
        }
        if exit_node {
            args.push("--advertise-exit-node");
        }
        match self.run(&args) {
            Ok(out) if out.status.success() => TailscaleResult {
                ok: true,
                detail: "routes advertised".into(),
            },
            Ok(out) => TailscaleResult {
                ok: false,
                detail: String::from_utf8_lossy(&out.stderr).trim().to_string(),
            },
            Err(e) => TailscaleResult {
                ok: false,
                detail: format!("tailscale set-routes failed: {e}"),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// status --json parsing
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct RawStatus {
    #[serde(rename = "BackendState")]
    backend_state: Option<String>,
    #[serde(rename = "Self")]
    self_info: Option<RawNode>,
    #[serde(rename = "Peer")]
    peers: Option<HashMap<String, RawNode>>,
    #[serde(rename = "ExitNodeStatus")]
    exit_node_status: Option<RawExitNode>,
    #[serde(rename = "Health")]
    health: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct RawExitNode {
    #[serde(rename = "Online")]
    online: Option<bool>,
}

#[derive(serde::Deserialize)]
struct RawNode {
    #[serde(rename = "HostName")]
    host_name: Option<String>,
    #[serde(rename = "DNSName")]
    dns_name: Option<String>,
    #[serde(rename = "TailscaleIPs")]
    tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "Online")]
    online: Option<bool>,
    #[serde(rename = "Active")]
    active: Option<bool>,
    #[serde(rename = "ExitNode")]
    exit_node: Option<bool>,
    #[serde(rename = "LastSeen")]
    last_seen: Option<String>,
    #[serde(rename = "Relay")]
    relay: Option<String>,
    #[serde(rename = "RxBytes")]
    rx_bytes: Option<u64>,
    #[serde(rename = "TxBytes")]
    tx_bytes: Option<u64>,
}

fn parse_status(raw: &[u8]) -> TailscaleStatus {
    let Ok(status): Result<RawStatus, _> = serde_json::from_slice(raw) else {
        return TailscaleStatus {
            installed: true,
            backend_state: "ParseError".into(),
            summary: "tailscale returned unparseable status".into(),
            ..Default::default()
        };
    };

    let backend_state = status.backend_state.unwrap_or_else(|| "Unknown".into());
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut peers = Vec::new();

    if let Some(node) = &status.self_info {
        for ip in node.tailscale_ips.clone().unwrap_or_default() {
            if ip.contains(':') {
                ipv6.push(ip);
            } else {
                ipv4.push(ip);
            }
        }
    }

    if let Some(peer_map) = &status.peers {
        for (_, peer) in peer_map {
            let last_seen_seconds_ago = peer.last_seen.as_ref().and_then(|ts| {
                chrono::DateTime::parse_from_rfc3339(ts)
                    .ok()
                    .map(|dt| dt.timestamp().max(0) as u64)
                    .and_then(|t| now.checked_sub(t))
            });
            peers.push(TailscalePeer {
                name: peer
                    .host_name
                    .clone()
                    .unwrap_or_else(|| peer.dns_name.clone().unwrap_or_default()),
                addrs: peer.tailscale_ips.clone().unwrap_or_default(),
                online: peer.online.unwrap_or(false),
                active: peer.active.unwrap_or(false),
                last_seen_seconds_ago,
                exit_node: peer.exit_node.unwrap_or(false),
                relay: peer.relay.clone(),
                rx_bytes: peer.rx_bytes,
                tx_bytes: peer.tx_bytes,
            });
        }
    }

    let exit_node = status
        .exit_node_status
        .as_ref()
        .and_then(|e| e.online)
        .unwrap_or(false)
        .then_some("exit node active".to_string());

    let self_online = status.self_info.as_ref().and_then(|n| n.online).unwrap_or(false);
    let tailscale_ip = status
        .self_info
        .as_ref()
        .and_then(|n| n.tailscale_ips.as_ref())
        .and_then(|ips| ips.first().cloned());
    let hostname = status
        .self_info
        .as_ref()
        .and_then(|n| n.host_name.clone())
        .or_else(|| status.self_info.as_ref().and_then(|n| n.dns_name.clone()));

    let health = status.health.unwrap_or_default();
    let summary = match backend_state.as_str() {
        "Running" => {
            if health.is_empty() {
                format!("Running · {} · {} peer(s)", tailscale_ip.as_deref().unwrap_or("?"), peers.len())
            } else {
                format!("Running · {} warning(s): {}", health.len(), health.join("; "))
            }
        }
        "NeedsLogin" => "Needs login — open the login URL from `tailscale up`".into(),
        "Stopped" => "Daemon stopped".into(),
        other => other.to_string(),
    };

    TailscaleStatus {
        installed: true,
        backend_state,
        self_online,
        hostname,
        tailscale_ip,
        ipv4,
        ipv6,
        peers,
        exit_node,
        advertise_routes: Vec::new(),
        uptime_seconds: None,
        summary,
    }
}

/// Driver used when the `tailscale` binary is absent. Reports the honest
/// "not installed" state and rejects operations.
pub struct AbsentTailscaleDriver;

#[async_trait]
impl TailscaleDriver for AbsentTailscaleDriver {
    async fn status(&self) -> TailscaleStatus {
        TailscaleStatus {
            installed: false,
            backend_state: "NotInstalled".into(),
            summary: "tailscale is not installed".into(),
            ..Default::default()
        }
    }
    async fn up(&self, _auth_key: Option<&str>) -> TailscaleResult {
        TailscaleResult {
            ok: false,
            detail: "tailscale is not installed".into(),
        }
    }
    async fn down(&self) -> TailscaleResult {
        TailscaleResult {
            ok: false,
            detail: "tailscale is not installed".into(),
        }
    }
    async fn reconnect(&self) -> TailscaleResult {
        TailscaleResult {
            ok: false,
            detail: "tailscale is not installed".into(),
        }
    }
    async fn set_routes(&self, _routes: &[String], _exit_node: bool) -> TailscaleResult {
        TailscaleResult {
            ok: false,
            detail: "tailscale is not installed".into(),
        }
    }
}

/// Driver for tests: returns a fixed status without any binary.
pub struct MockTailscaleDriver {
    status: TailscaleStatus,
}

impl MockTailscaleDriver {
    pub fn new(status: TailscaleStatus) -> Self {
        Self { status }
    }
}

#[async_trait]
impl TailscaleDriver for MockTailscaleDriver {
    async fn status(&self) -> TailscaleStatus {
        self.status.clone()
    }
    async fn up(&self, _auth_key: Option<&str>) -> TailscaleResult {
        TailscaleResult { ok: true, detail: "mock up".into() }
    }
    async fn down(&self) -> TailscaleResult {
        TailscaleResult { ok: true, detail: "mock down".into() }
    }
    async fn reconnect(&self) -> TailscaleResult {
        TailscaleResult { ok: true, detail: "mock reconnect".into() }
    }
    async fn set_routes(&self, _routes: &[String], _exit_node: bool) -> TailscaleResult {
        TailscaleResult { ok: true, detail: "mock routes".into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_validation() {
        assert!(validate_route("10.0.0.0/24"));
        assert!(validate_route("192.168.1.0/24"));
        assert!(validate_route("2001:db8::/32"));
        assert!(!validate_route("10.0.0.0/33"));
        assert!(!validate_route("10.0.0.0"));
        assert!(!validate_route("10.0.0.0/24; rm -rf /"));
        assert!(!validate_route("0.0.0.0/0"));
        assert!(!validate_route("300.1.1.1/24"));
    }

    #[test]
    fn parse_running_status() {
        let json = br#"{
          "BackendState": "Running",
          "Self": {
            "HostName": "edge",
            "DNSName": "edge.tailnet.ts.net",
            "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
            "Online": true
          },
          "Peer": {
            "n1": {
              "HostName": "laptop",
              "TailscaleIPs": ["100.64.0.2"],
              "Online": true,
              "Active": false,
              "LastSeen": "2026-08-13T12:00:00Z",
              "RxBytes": 1024,
              "TxBytes": 2048
            }
          }
        }"#;
        let status = parse_status(json);
        assert_eq!(status.backend_state, "Running");
        assert!(status.self_online);
        assert_eq!(status.ipv4, vec!["100.64.0.1"]);
        assert_eq!(status.ipv6.len(), 1);
        assert_eq!(status.peers.len(), 1);
        assert_eq!(status.peers[0].name, "laptop");
        assert_eq!(status.peers[0].rx_bytes, Some(1024));
        assert!(status.summary.contains("Running"));
    }

    #[test]
    fn parse_needs_login() {
        let status = parse_status(br#"{"BackendState": "NeedsLogin"}"#);
        assert_eq!(status.backend_state, "NeedsLogin");
        assert!(status.summary.contains("Needs login"));
    }

    #[test]
    fn parse_garbage_is_honest() {
        let status = parse_status(b"not json");
        assert_eq!(status.backend_state, "ParseError");
    }
}
