//! Gateway datapath types (`MsgType::GatewayOp`).
//!
//! The daemon owns the *desired* gateway topology (explicit WAN/LAN roles from
//! `network_config.rs`). This typed operation carries that intent to the
//! executor, which is the *only* component that touches `sysctl`/nftables NAT
//! state. The executor renders and applies the real rules (masquerade/SNAT,
//! conntrack, management firewall) idempotently and can tear them down again —
//! so NAT is a real datapath, not an enum/IPC declaration.

use serde::{Deserialize, Serialize};

/// Gateway datapath intent computed by the daemon.
///
/// Only the daemon decides *what* the topology should be; the executor decides
/// *how* to render it into nftables/sysctl. Validation is defensive on both
/// sides (the executor re-validates before touching the kernel).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Interface facing the provider (ISP uplink). Masquerade/SNAT targets it.
    pub wan_interface: String,
    /// Interface facing the LAN. The management firewall allows admin ports
    /// only from this interface's subnet.
    pub lan_interface: String,
    /// LAN subnet CIDR (e.g. `192.168.3.0/24`) used by the management firewall
    /// to scope admin access to LAN peers.
    pub lan_subnet: String,
}

impl GatewayConfig {
    /// Validate that the topology intent is well-formed (before any IPC).
    ///
    /// Interface names must be simple identifiers (never empty, no whitespace,
    /// no path separators — the executor builds nft expressions and sysctl
    /// paths from them). The subnet must parse as an IPv4 or IPv6 CIDR.
    pub fn validate(&self) -> Result<(), String> {
        validate_iface(&self.wan_interface, "wan_interface")?;
        validate_iface(&self.lan_interface, "lan_interface")?;
        if self.wan_interface == self.lan_interface {
            return Err("gateway config: wan_interface and lan_interface must differ".into());
        }
        parse_cidr(&self.lan_subnet).map_err(|e| format!("gateway config: lan_subnet: {e}"))?;
        Ok(())
    }
}

fn validate_iface(name: &str, field: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("gateway config: {field} must not be empty"));
    }
    if name.len() > 15 {
        return Err(format!("gateway config: {field} too long: {name:?}"));
    }
    let valid = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !valid {
        return Err(format!("gateway config: {field} has invalid characters: {name:?}"));
    }
    Ok(())
}

fn parse_cidr(cidr: &str) -> Result<std::net::IpAddr, String> {
    let addr = cidr
        .rsplit_once('/')
        .map(|(a, _)| a)
        .unwrap_or(cidr);
    addr.parse::<std::net::IpAddr>()
        .map_err(|_| format!("invalid CIDR: {cidr:?}"))
}

/// Default management ports allowed from LAN to the RPi itself.
pub const DEFAULT_MGMT_PORTS: &[u16] = &[22, 53, 8080, 9090];

/// A gateway datapath operation (`MsgType::GatewayOp`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayOp {
    /// Apply (or re-apply idempotently) the full gateway datapath: IP
    /// forwarding, NAT (MASQUERADE/SNAT on the WAN interface), conntrack
    /// handling, and the management firewall. Re-running converges to the same
    /// rules (never duplicates).
    Apply(GatewayConfig),
    /// Remove the gateway datapath rules the executor installed. IP forwarding
    /// is left enabled only if something else enabled it (the executor records
    /// the prior sysctl value); rules are always torn down.
    Remove,
    /// Report the currently applied gateway state (non-authority, like the rule
    /// inventory — the daemon reconciles against it).
    Status,
}

/// Result of a gateway datapath operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayResult {
    pub ok: bool,
    /// Human-readable detail (e.g. which rules were applied).
    pub detail: String,
}

/// Applied gateway datapath state reported by `GatewayOp::Status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GatewayStatus {
    /// Whether the gateway datapath is currently applied (NAT + forwarding).
    pub enabled: bool,
    /// The WAN interface masquerade is bound to, when applied.
    pub wan_interface: Option<String>,
    /// The LAN interface the management firewall scopes to, when applied.
    pub lan_interface: Option<String>,
    /// The LAN subnet the management firewall allows admin ports from.
    pub lan_subnet: Option<String>,
    /// Whether `net.ipv4.ip_forward` is currently `1`.
    pub ip_forward_enabled: bool,
    /// Management firewall rules applied (LAN→RPi allow set).
    pub mgmt_ports: Vec<u16>,
    /// Whether management firewall blocks non-LAN input.
    pub wan_input_blocked: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_config_validation() {
        let good = GatewayConfig {
            wan_interface: "eth1".into(),
            lan_interface: "eth0".into(),
            lan_subnet: "192.168.3.0/24".into(),
        };
        assert!(good.validate().is_ok());

        // Same interface for WAN and LAN is invalid (roles must differ).
        let same = GatewayConfig {
            wan_interface: "eth0".into(),
            lan_interface: "eth0".into(),
            lan_subnet: "192.168.3.0/24".into(),
        };
        assert!(same.validate().is_err());

        // Empty / path-injected interface names are rejected.
        for bad in ["", "../evil", "wan iface", "a/../b", &"x".repeat(20)] {
            let cfg = GatewayConfig {
                wan_interface: bad.into(),
                lan_interface: "eth0".into(),
                lan_subnet: "192.168.3.0/24".into(),
            };
            assert!(cfg.validate().is_err(), "{bad:?} must be rejected");
        }

        // IPv6 subnet is acceptable; garbage is not.
        let v6 = GatewayConfig {
            wan_interface: "eth1".into(),
            lan_interface: "eth0".into(),
            lan_subnet: "fd00::/64".into(),
        };
        assert!(v6.validate().is_ok());
        let bad_subnet = GatewayConfig {
            wan_interface: "eth1".into(),
            lan_interface: "eth0".into(),
            lan_subnet: "not-a-cidr".into(),
        };
        assert!(bad_subnet.validate().is_err());
    }
}
