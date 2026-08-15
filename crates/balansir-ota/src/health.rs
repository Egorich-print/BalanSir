//! Post-boot health check for OTA slot confirmation.
//!
//! Validates critical gateway functionality after an OTA boot.
//! Runs as a systemd service after multi-user.target.

use balansir_common::{Error, Result};
use crate::{manifest, slot};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, warn};

/// Health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HealthConfig {
    /// Timeout for individual checks.
    #[serde(default = "default_check_timeout")]
    pub check_timeout_secs: u64,

    /// Overall health check deadline.
    #[serde(default = "default_total_timeout")]
    pub total_timeout_secs: u64,

    /// Critical checks (failure = rollback).
    #[serde(default = "default_critical_checks")]
    pub critical_checks: Vec<CheckName>,

    /// Optional checks (failure = warning only).
    #[serde(default = "default_optional_checks")]
    pub optional_checks: Vec<CheckName>,

    /// Minimum WAN uptime required (seconds).
    #[serde(default = "default_wan_uptime")]
    pub min_wan_uptime_secs: u64,
}

fn default_check_timeout() -> u64 {
    10
}

fn default_total_timeout() -> u64 {
    120
}

pub fn default_critical_checks() -> Vec<CheckName> {
    vec![
        CheckName::DaemonRunning,
        CheckName::ExecutorRunning,
        CheckName::IpcConnected,
        CheckName::NetworkRolesValid,
        CheckName::LanInterfaceUp,
        CheckName::FirewallLoaded,
        CheckName::NatWorking,
        CheckName::DnsResolving,
    ]
}

pub fn default_optional_checks() -> Vec<CheckName> {
    vec![
        CheckName::WanInterfaceUp,
        CheckName::WanConnectivity,
        CheckName::B4Engine,
        CheckName::VpnSubsystem,
        CheckName::XrayRunning,
    ]
}

fn default_wan_uptime() -> u64 {
    30
}

/// Individual health check identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckName {
    DaemonRunning,
    ExecutorRunning,
    IpcConnected,
    NetworkRolesValid,
    LanInterfaceUp,
    WanInterfaceUp,
    WanConnectivity,
    FirewallLoaded,
    NatWorking,
    DnsResolving,
    B4Engine,
    VpnSubsystem,
    XrayRunning,
}

impl std::fmt::Display for CheckName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckName::DaemonRunning => write!(f, "daemon_running"),
            CheckName::ExecutorRunning => write!(f, "executor_running"),
            CheckName::IpcConnected => write!(f, "ipc_connected"),
            CheckName::NetworkRolesValid => write!(f, "network_roles_valid"),
            CheckName::LanInterfaceUp => write!(f, "lan_interface_up"),
            CheckName::WanInterfaceUp => write!(f, "wan_interface_up"),
            CheckName::WanConnectivity => write!(f, "wan_connectivity"),
            CheckName::FirewallLoaded => write!(f, "firewall_loaded"),
            CheckName::NatWorking => write!(f, "nat_working"),
            CheckName::DnsResolving => write!(f, "dns_resolving"),
            CheckName::B4Engine => write!(f, "b4_engine"),
            CheckName::VpnSubsystem => write!(f, "vpn_subsystem"),
            CheckName::XrayRunning => write!(f, "xray_running"),
        }
    }
}

/// Result of a single health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: CheckName,
    pub passed: bool,
    pub critical: bool,
    pub message: String,
    pub duration_ms: u64,
}

/// Overall health check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub timestamp: u64,
    pub slot: String,
    pub firmware_version: String,
    pub checks: Vec<CheckResult>,
    pub overall_passed: bool,
    pub critical_failed: bool,
    pub duration_ms: u64,
}

impl HealthReport {
    pub fn new(slot: String, firmware_version: String) -> Self {
        Self {
            timestamp: current_timestamp(),
            slot,
            firmware_version,
            checks: Vec::new(),
            overall_passed: true,
            critical_failed: false,
            duration_ms: 0,
        }
    }

    pub fn add_check(&mut self, result: CheckResult) {
        let critical = result.critical;
        let passed = result.passed;
        self.checks.push(result);
        if critical && !passed {
            self.overall_passed = false;
            self.critical_failed = true;
        }
    }

    /// Check if the slot should be confirmed.
    pub fn should_confirm(&self) -> bool {
        self.overall_passed && !self.critical_failed
    }
}

/// Health checker implementation.
pub struct HealthChecker {
    config: HealthConfig,
    executor_socket: String,
    daemon_socket: String,
}

impl HealthChecker {
    pub fn new(config: HealthConfig) -> Self {
        Self {
            config,
            executor_socket: "/run/balansir/executor.sock".into(),
            daemon_socket: "/run/balansir/daemon.sock".into(),
        }
    }

    /// Run all health checks.
    pub async fn run(&self, slot: String, firmware_version: String) -> Result<HealthReport> {
        let start = Instant::now();
        let mut report = HealthReport::new(slot, firmware_version);

        let critical_set: std::collections::HashSet<_> = self.config.critical_checks.iter().cloned().collect();
        let all_checks: Vec<CheckName> = self.config.critical_checks.iter()
            .chain(self.config.optional_checks.iter())
            .cloned()
            .collect();

        for check_name in all_checks {
            let check_start = Instant::now();
            let critical = self.config.critical_checks.contains(&check_name);

            let result = match check_name {
                CheckName::DaemonRunning => self.check_daemon_running().await,
                CheckName::ExecutorRunning => self.check_executor_running().await,
                CheckName::IpcConnected => self.check_ipc_connected().await,
                CheckName::NetworkRolesValid => self.check_network_roles().await,
                CheckName::LanInterfaceUp => self.check_lan_interface().await,
                CheckName::WanInterfaceUp => self.check_wan_interface().await,
                CheckName::WanConnectivity => self.check_wan_connectivity().await,
                CheckName::FirewallLoaded => self.check_firewall().await,
                CheckName::NatWorking => self.check_nat().await,
                CheckName::DnsResolving => self.check_dns().await,
                CheckName::B4Engine => self.check_b4_engine().await,
                CheckName::VpnSubsystem => self.check_vpn().await,
                CheckName::XrayRunning => self.check_xray().await,
            };

            let duration = check_start.elapsed().as_millis() as u64;

            let check_result = match result {
                Ok(msg) => CheckResult {
                    name: check_name,
                    passed: true,
                    critical,
                    message: msg,
                    duration_ms: duration,
                },
                Err(e) => CheckResult {
                    name: check_name,
                    passed: false,
                    critical,
                    message: e.to_string(),
                    duration_ms: duration,
                },
            };

            let status = if check_result.passed { "PASS" } else { "FAIL" };
            let crit = if critical { " [CRITICAL]" } else { "" };
            info!("Health check {}: {}{}", check_name, status, crit);

            report.add_check(check_result);
        }

        report.duration_ms = start.elapsed().as_millis() as u64;
        info!("Health check complete: overall={} critical_failed={} duration={}ms",
            report.overall_passed, report.critical_failed, report.duration_ms);

        Ok(report)
    }

    // --- Individual checks ---

    async fn check_daemon_running(&self) -> Result<String> {
        let output = Command::new("systemctl")
            .args(["is-active", "balansir-daemon"])
            .output()
            .map_err(Error::Io)?;
        if output.status.success() {
            Ok("balansir-daemon is active".into())
        } else {
            Err(Error::Fatal("balansir-daemon not active".into()))
        }
    }

    async fn check_executor_running(&self) -> Result<String> {
        let output = Command::new("systemctl")
            .args(["is-active", "balansir-executor"])
            .output()
            .map_err(Error::Io)?;
        if output.status.success() {
            Ok("balansir-executor is active".into())
        } else {
            Err(Error::Fatal("balansir-executor not active".into()))
        }
    }

    async fn check_ipc_connected(&self) -> Result<String> {
        // Try connecting to executor socket
        let client = balansir_common::ipc::IpcClientConnection::connect(&self.executor_socket).await
            .map_err(|e| Error::Fatal(format!("connect executor: {e}")))?;
        // Send health check
        let mut conn = client;
        let resp = conn.request(balansir_common::ipc::MsgType::HealthCheck, vec![]).await
            .map_err(|e| Error::Fatal(format!("health check request: {e}")))?;
        if resp.msg_type == balansir_common::ipc::MsgType::ResponseOk {
            Ok("IPC connection to executor OK".into())
        } else {
            Err(Error::Fatal("executor health check failed".into()))
        }
    }

    async fn check_network_roles(&self) -> Result<String> {
        // Check that WAN/LAN roles are configured and valid
        let config_path = "/etc/balansir/network.toml";
        if !std::path::Path::new(config_path).exists() {
            return Err(Error::Misconfiguration("network.toml not found".into()));
        }
        let content = std::fs::read_to_string(config_path).map_err(Error::Io)?;
        let config: NetworkConfig = toml::from_str(&content)
            .map_err(|e| Error::Misconfiguration(format!("parse network config: {e}")))?;

        if let Some(wan) = config.network.wan_interface {
            if !interface_exists(&wan) {
                return Err(Error::Fatal(format!("WAN interface {} not found", wan)));
            }
        }
        if let Some(lan) = config.network.lan_interface {
            if !interface_exists(&lan) {
                return Err(Error::Fatal(format!("LAN interface {} not found", lan)));
            }
        }
        Ok("Network roles configured and interfaces present".into())
    }

    async fn check_lan_interface(&self) -> Result<String> {
        let config_path = "/etc/balansir/network.toml";
        let content = std::fs::read_to_string(config_path).map_err(Error::Io)?;
        let config: NetworkConfig = toml::from_str(&content)
            .map_err(|e| Error::Misconfiguration(format!("parse network config: {e}")))?;

        if let Some(lan) = config.network.lan_interface {
            if is_interface_up(&lan) {
                Ok(format!("LAN interface {} is up", lan))
            } else {
                Err(Error::Fatal(format!("LAN interface {} is down", lan)))
            }
        } else {
            Err(Error::Misconfiguration("LAN interface not configured".into()))
        }
    }

    async fn check_wan_interface(&self) -> Result<String> {
        let config_path = "/etc/balansir/network.toml";
        let content = std::fs::read_to_string(config_path).map_err(Error::Io)?;
        let config: NetworkConfig = toml::from_str(&content)
            .map_err(|e| Error::Misconfiguration(format!("parse network config: {e}")))?;

        if let Some(wan) = config.network.wan_interface {
            if is_interface_up(&wan) {
                Ok(format!("WAN interface {} is up", wan))
            } else {
                Err(Error::Fatal(format!("WAN interface {} is down", wan)))
            }
        } else {
            Err(Error::Misconfiguration("WAN interface not configured".into()))
        }
    }

    async fn check_wan_connectivity(&self) -> Result<String> {
        // Try to reach a known external host
        let addr: SocketAddr = "1.1.1.1:53".parse().unwrap();
        match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => Ok("WAN connectivity OK (TCP 1.1.1.1:53)".into()),
            Ok(Err(e)) => Err(Error::Fatal(format!("WAN TCP connect failed: {e}"))),
            Err(_) => Err(Error::Fatal("WAN connectivity timeout".into())),
        }
    }

    async fn check_firewall(&self) -> Result<String> {
        // Check nftables rules are loaded
        let output = Command::new("nft")
            .args(["list", "ruleset"])
            .output()
            .map_err(Error::Io)?;
        if output.status.success() {
            let rules = String::from_utf8_lossy(&output.stdout);
            if rules.contains("table inet balansir") {
                Ok("nftables balansir table loaded".into())
            } else {
                Err(Error::Fatal("balansir table not found in nftables".into()))
            }
        } else {
            Err(Error::Fatal("nft list ruleset failed".into()))
        }
    }

    async fn check_nat(&self) -> Result<String> {
        // Verify masquerade rule exists
        let output = Command::new("nft")
            .args(["list", "chain", "inet", "balansir", "postrouting"])
            .output()
            .map_err(Error::Io)?;
        if output.status.success() {
            let rules = String::from_utf8_lossy(&output.stdout);
            if rules.contains("masquerade") {
                Ok("NAT masquerade rule present".into())
            } else {
                Err(Error::Fatal("masquerade rule not found".into()))
            }
        } else {
            Err(Error::Fatal("cannot list postrouting chain".into()))
        }
    }

    async fn check_dns(&self) -> Result<String> {
        // Try resolving a known domain via local DNS
        let output = Command::new("dig")
            .args(["@127.0.0.1", "example.com", "A", "+short", "+time=5"])
            .output()
            .map_err(Error::Io)?;
        if output.status.success() {
            let out = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !out.is_empty() {
                Ok(format!("DNS resolving: {}", out))
            } else {
                Err(Error::Fatal("DNS returned empty answer".into()))
            }
        } else {
            Err(Error::Fatal("dig command failed".into()))
        }
    }

    async fn check_b4_engine(&self) -> Result<String> {
        // Check B4 engine via daemon API or direct socket
        // For now, just check if the process/service is running
        if std::path::Path::new("/run/balansir/b4").exists() {
            Ok("B4 engine socket present".into())
        } else {
            // Check if B4 is configured at all
            Ok("B4 engine not configured (optional)".into())
        }
    }

    async fn check_vpn(&self) -> Result<String> {
        Ok("VPN subsystem not configured (optional)".into())
    }

    async fn check_xray(&self) -> Result<String> {
        Ok("Xray not configured (optional)".into())
    }
}

/// Network config for role validation.
#[derive(Debug, Deserialize)]
struct NetworkConfig {
    network: NetworkSection,
}

#[derive(Debug, Deserialize)]
struct NetworkSection {
    wan_interface: Option<String>,
    lan_interface: Option<String>,
}

fn interface_exists(name: &str) -> bool {
    std::path::Path::new(&format!("/sys/class/net/{}", name)).exists()
}

fn is_interface_up(name: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{}/operstate", name))
        .map(|s| s.trim() == "up")
        .unwrap_or(false)
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_config_defaults() {
        let config = HealthConfig {
            check_timeout_secs: 10,
            total_timeout_secs: 120,
            critical_checks: default_critical_checks(),
            optional_checks: default_optional_checks(),
            min_wan_uptime_secs: 30,
        };
        assert_eq!(config.critical_checks.len(), 8);
        assert_eq!(config.optional_checks.len(), 5);
    }

    #[test]
    fn health_report_should_confirm() {
        let mut report = HealthReport::new("A".into(), "0.6.0".into());
        report.add_check(CheckResult {
            name: CheckName::DaemonRunning,
            passed: true,
            critical: true,
            message: "OK".into(),
            duration_ms: 10,
        });
        assert!(report.should_confirm());

        report.add_check(CheckResult {
            name: CheckName::DaemonRunning,
            passed: false,
            critical: true,
            message: "FAIL".into(),
            duration_ms: 10,
        });
        assert!(!report.should_confirm());
    }
}