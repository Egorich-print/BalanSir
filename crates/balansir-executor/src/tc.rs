//! QoS / traffic shaping backend (Rust-native, LibreQoS-inspired).
//!
//! Uses the kernel's HTB + fq_codel qdiscs via the `tc` CLI. The executor is
//! the privileged boundary that owns applied shaping state (non-authority; the
//! daemon decides what *should* be applied and reconciles). Idempotent:
//! applying the same plan is a no-op; clearing removes the root qdisc.

use balansir_common::error::{Error, Result};
use balansir_common::{QosPlan, QosState};
use std::path::PathBuf;
use std::process::Command;
use tracing::info;

fn tc_bin() -> Result<PathBuf> {
    balansir_common::paths::resolve_bin("tc")
        .ok_or_else(|| Error::Misconfiguration("tc binary not found".into()))
}

/// Validate an interface name / class id to avoid CLI injection.
fn validate_identifier(name: &str) -> Result<()> {
    if !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        Ok(())
    } else {
        Err(Error::Misconfiguration(format!(
            "invalid tc identifier: {:?}",
            name
        )))
    }
}

fn validate_rate(rate_bits: u64) -> Result<u64> {
    if rate_bits >= 1000 {
        Ok(rate_bits)
    } else {
        Err(Error::Misconfiguration(format!(
            "rate too small for tc: {rate_bits} bits"
        )))
    }
}

/// Render a bit rate in tc `x kbit` notation (tc requires integer kbit).
fn rate_kbit(rate_bits: u64) -> String {
    let kbit = rate_bits.div_ceil(1000).max(1);
    format!("{kbit}kbit")
}

#[derive(Debug, Default)]
pub struct TcBackend;

impl TcBackend {
    fn run(args: &[&str]) -> Result<()> {
        let bin = tc_bin()?;
        let out = Command::new(&bin)
            .args(args)
            .output()
            .map_err(|e| Error::Fatal(format!("failed to run tc: {e}")))?;
        if out.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(Error::Fatal(format!(
                "tc {} failed: {}",
                args.join(" "),
                stderr.trim()
            )))
        }
    }

    /// Return true when the interface already has a root qdisc (any).
    fn has_root_qdisc(interface: &str) -> bool {
        let Ok(bin) = tc_bin() else {
            return false;
        };
        let out = Command::new(&bin)
            .args(["qdisc", "show", "dev", interface])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                !String::from_utf8_lossy(&o.stdout).contains("qdisc pfifo")
            }
            _ => false,
        }
    }

    /// Apply an HTB root + fq_codel leaf per class. Idempotent per interface:
    /// if a non-default root qdisc exists, we replace it atomically.
    pub fn apply_plan(&self, plan: &QosPlan) -> Result<()> {
        validate_identifier(&plan.interface)?;
        let default_rate = validate_rate(plan.default_rate_bits)?;
        let default_ceil = validate_rate(plan.default_ceil_bits)?;
        for c in &plan.classes {
            validate_rate(c.rate_bits)?;
            validate_rate(c.ceil_bits)?;
        }
        if plan.default_ceil_bits < plan.default_rate_bits {
            return Err(Error::Misconfiguration(
                "default_ceil must be >= default_rate".into(),
            ));
        }

        if Self::has_root_qdisc(&plan.interface) {
            // Existing (possibly stale) shaping: delete then re-add.
            Self::run(&["qdisc", "del", "dev", &plan.interface, "root"])?;
        }

        let iface = &plan.interface;
        Self::run(&[
            "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "1",
        ])?;
        Self::run(&[
            "class",
            "add",
            "dev",
            iface,
            "parent",
            "1:",
            "classid",
            "1:1",
            "htb",
            "rate",
            &rate_kbit(default_rate),
            "ceil",
            &rate_kbit(default_ceil),
        ])?;
        Self::run(&[
            "qdisc", "add", "dev", iface, "parent", "1:1", "handle", "10:", "fq_codel",
        ])?;

        for class in &plan.classes {
            let minor = format!("1:{}", class.class_id);
            let handle = format!("{}0:", class.class_id);
            Self::run(&[
                "class",
                "add",
                "dev",
                iface,
                "parent",
                "1:1",
                "classid",
                &minor,
                "htb",
                "rate",
                &rate_kbit(class.rate_bits),
                "ceil",
                &rate_kbit(class.ceil_bits),
            ])?;
            Self::run(&[
                "qdisc", "add", "dev", iface, "parent", &minor, "handle", &handle, "fq_codel",
            ])?;
        }

        info!(
            "qos applied on {}: {} classes, default rate {} kbit",
            plan.interface,
            plan.classes.len(),
            rate_kbit(default_rate)
        );
        Ok(())
    }

    /// Remove shaping on an interface (idempotent).
    pub fn clear_plan(&self, interface: &str) -> Result<()> {
        validate_identifier(interface)?;
        if Self::has_root_qdisc(interface) {
            Self::run(&["qdisc", "del", "dev", interface, "root"])?;
            info!("qos cleared on {interface}");
        }
        Ok(())
    }

    /// Report interfaces that currently carry a non-default root qdisc
    /// (shaping applied) — the executor's applied-state inventory.
    pub fn state(&self, interfaces: &[String]) -> Result<QosState> {
        let mut applied = Vec::new();
        for iface in interfaces {
            let Ok(bin) = tc_bin() else {
                break;
            };
            let out = Command::new(&bin)
                .args(["qdisc", "show", "dev", iface])
                .output();
            if let Ok(o) = out {
                if o.status.success() && !String::from_utf8_lossy(&o.stdout).contains("qdisc pfifo")
                {
                    applied.push(iface.clone());
                }
            }
        }
        Ok(QosState {
            interfaces: applied,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_rendering_is_integer_kbit() {
        assert_eq!(rate_kbit(1_000_000), "1000kbit");
        assert_eq!(rate_kbit(2_000_000), "2000kbit");
        assert_eq!(rate_kbit(1_500), "2kbit"); // ceil-division
    }

    #[test]
    fn rejects_undersized_rates() {
        assert!(validate_rate(0).is_err());
        assert!(validate_rate(1).is_err());
        assert!(validate_rate(500).is_err());
        assert!(validate_rate(1000).is_ok());
    }

    #[test]
    fn validates_identifiers() {
        assert!(validate_identifier("eth0").is_ok());
        assert!(validate_identifier("br-lan.10").is_ok());
        assert!(validate_identifier("eth0; rm -rf").is_err());
        assert!(validate_identifier("").is_err());
    }

    #[test]
    fn state_defaults_to_empty() {
        let backend = TcBackend;
        let state = backend.state(&[]).unwrap();
        assert!(state.interfaces.is_empty());
    }
}
