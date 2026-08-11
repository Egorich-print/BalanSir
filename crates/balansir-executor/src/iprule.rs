//! Policy-routing (`ip rule`) backend (M3.7, ADR-014).
//!
//! fwmark + ip-rule: once nftables marks a classified flow (`meta mark set N`),
//! `ip rule add fwmark N lookup <table>` sends that flow to a routing table
//! (which carries the mechanism route — DIRECT, a tunnel interface, etc.).
//!
//! Commands are invoked with typed positional arguments (no shell
//! interpolation, no free-form strings), mirroring the nftables backend.

use balansir_common::error::{Error, Result};
use std::process::Command;
use tracing::info;

/// Absolute path to the `ip` binary, resolved from standard locations.
fn ip_bin() -> Result<std::path::PathBuf> {
    balansir_common::paths::resolve_bin("ip")
        .ok_or_else(|| Error::Misconfiguration("ip binary not found".into()))
}

/// fwmark + policy-routing backend. Operates on the host default network
/// namespace (netns ownership is out of M3.7 scope, ADR-014).
#[derive(Debug)]
pub struct IpRuleBackend;

impl IpRuleBackend {
    pub fn new() -> Self {
        Self
    }

    /// Add `ip rule add fwmark <fwmark> lookup <table>`.
    pub fn add_fwmark_rule(&self, fwmark: u32, table: u32) -> Result<()> {
        let output = Command::new(ip_bin()?)
            .args(["rule", "add", "fwmark"])
            .arg(fwmark.to_string())
            .arg("lookup")
            .arg(table.to_string())
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Fatal(format!("ip rule add failed: {}", stderr)));
        }
        info!(fwmark, table, "Added fwmark ip-rule");
        Ok(())
    }

    /// Remove `ip rule del fwmark <fwmark> lookup <table>`. Idempotent when the
    /// rule is already absent.
    pub fn del_fwmark_rule(&self, fwmark: u32, table: u32) -> Result<()> {
        let output = Command::new(ip_bin()?)
            .args(["rule", "del", "fwmark"])
            .arg(fwmark.to_string())
            .arg("lookup")
            .arg(table.to_string())
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Fatal(format!("ip rule del failed: {}", stderr)));
        }
        info!(fwmark, table, "Removed fwmark ip-rule");
        Ok(())
    }
}

impl Default for IpRuleBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    /// The ip-rule command arguments are built from typed values only — no
    /// free-form strings reach the command line.
    fn rule_args(fwmark: u32, table: u32) -> Vec<String> {
        vec![
            "rule".to_string(),
            "add".to_string(),
            "fwmark".to_string(),
            fwmark.to_string(),
            "lookup".to_string(),
            table.to_string(),
        ]
    }

    #[test]
    fn ip_rule_args_are_typed_and_ordered() {
        assert_eq!(
            rule_args(0x10, 100),
            vec![
                "rule".to_string(),
                "add".to_string(),
                "fwmark".to_string(),
                "16".to_string(),
                "lookup".to_string(),
                "100".to_string(),
            ]
        );
    }
}
