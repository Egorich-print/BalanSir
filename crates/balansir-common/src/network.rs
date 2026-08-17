//! Network interface / WAN identity / Tailscale status model.
//!
//! These types cross the daemon/executor boundary (IPC) and are also rendered
//! by the API and WebUI. WAN identity support deliberately preserves the
//! hardware MAC: the executor records it at first use and restores it on
//! removal, so MAC cloning never destroys the original factory address.
//!
//! # Interface Roles
//!
//! BalanSir classifies each interface into a role (WAN, LAN, MANAGEMENT, UNKNOWN).
//! Roles are determined by configuration, not by interface names — the core
//! never assumes `eth0` = WAN or `eth1` = LAN.

use serde::{Deserialize, Serialize};

/// Network interface role — determined by configuration and observable
/// properties, never by interface name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceRole {
    /// WAN (provider-facing) interface. NAT masquerade applied here.
    Wan,
    /// LAN (client-facing) interface. Management access scoped here.
    Lan,
    /// Management-only interface (e.g. Tailscale, debug console).
    Management,
    /// Unknown / not yet classified.
    #[default]
    Unknown,
}

impl InterfaceRole {
    pub fn label(&self) -> &'static str {
        match self {
            InterfaceRole::Wan => "WAN",
            InterfaceRole::Lan => "LAN",
            InterfaceRole::Management => "Mgmt",
            InterfaceRole::Unknown => "Unknown",
        }
    }
}

/// Snapshot of one kernel interface (netlink `RTM_GETLINK`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub index: i32,
    pub kind: Option<String>,
    pub mac: Option<String>,
    /// Assigned role (WAN/LAN/Management/Unknown). Determined by
    /// configuration or automatic detection, never by name.
    #[serde(default)]
    pub role: InterfaceRole,
    /// Factory (permanent) MAC from `IFLA_PERM_ADDRESS`, when the kernel
    /// exposes one. Never overwritten by MAC cloning.
    #[serde(default)]
    pub hardware_mac: Option<String>,
    /// The MAC that was in effect before the last clone (executor-side
    /// remember/restore state), used for safe restore and WAN identity.
    #[serde(default)]
    pub previous_mac: Option<String>,
    /// Link is administratively UP and carrier present.
    pub link_up: bool,
    pub mtu: u32,
    pub speed_mbps: Option<u64>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    /// Live counters (if available).
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub multicast: u64,
    pub qdisc: Option<String>,
    pub oper_state: Option<String>,
}

/// WAN identity: how the device presents itself to the ISP.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WanIdentity {
    pub interface: String,
    /// Factory MAC as first observed (never overwritten).
    pub hardware_mac: Option<String>,
    /// MAC currently configured on the interface.
    pub current_mac: Option<String>,
    /// MAC requested by the operator (MAC cloning target), if set.
    pub configured_mac: Option<String>,
    /// Whether the operator-requested MAC differs from hardware.
    pub cloning_active: bool,
    pub mtu: u32,
    pub link_up: bool,
    pub dhcp: WanDhcpState,
}

/// DHCP observation for the WAN interface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WanDhcpState {
    pub observed: bool,
    pub ip: Option<String>,
    pub gateway: Option<String>,
    pub dns: Vec<String>,
    pub lease_seconds: Option<u32>,
    pub hostname: Option<String>,
}

/// Tailscale daemon/network status (reported by the executor's `tailscale`
/// driver; never exposes secrets).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleStatus {
    /// Whether the `tailscale` binary and `tailscaled` are present.
    pub installed: bool,
    pub backend_state: String,
    pub self_online: bool,
    pub hostname: Option<String>,
    pub tailscale_ip: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub peers: Vec<TailscalePeer>,
    pub exit_node: Option<String>,
    pub advertise_routes: Vec<String>,
    pub uptime_seconds: Option<u64>,
    /// Human-readable summary suitable for the WebUI.
    pub summary: String,
}

/// One Tailscale peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscalePeer {
    pub name: String,
    pub addrs: Vec<String>,
    pub online: bool,
    pub active: bool,
    pub last_seen_seconds_ago: Option<u64>,
    pub exit_node: bool,
    pub relay: Option<String>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

/// A request to the executor's Tailscale driver. Argument lists are validated
/// by the executor against an allowlist before any binary is spawned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TailscaleOp {
    /// Query `tailscale status --json`.
    Status,
    /// Bring the daemon up (`tailscale up`). `auth_key` is optional and is
    /// never stored or logged.
    Up { auth_key: Option<String> },
    /// Bring the daemon down (`tailscale down`).
    Down,
    /// Reconnect / re-authenticate.
    Reconnect,
    /// Advertise (or remove) subnet routes.
    SetRoutes {
        routes: Vec<String>,
        exit_node: bool,
    },
}

/// Result of a Tailscale operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailscaleResult {
    pub ok: bool,
    pub detail: String,
}

/// A request to the executor's interface driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceOp {
    /// Read interface info (by name) or all interfaces when name is empty.
    Get { interface: String },
    /// Clone a MAC. `mac` is validated by the executor. Hardware MAC is
    /// recorded (once) and restored on `Restore`.
    SetMac { interface: String, mac: String },
    /// Restore the factory MAC (safe undo of cloning).
    RestoreMac { interface: String },
}

/// Result of an interface operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceResult {
    pub ok: bool,
    pub detail: String,
    pub hardware_mac: Option<String>,
    pub current_mac: Option<String>,
    /// The MAC that was in effect before the last clone, when known (used for
    /// safe restore on interfaces without a permanent hardware address).
    #[serde(default)]
    pub previous_mac: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_info_default_is_empty() {
        let info = InterfaceInfo::default();
        assert!(info.ipv4.is_empty() && info.ipv6.is_empty());
        assert_eq!(info.index, 0);
    }

    #[test]
    fn tailscale_status_roundtrip() {
        let status = TailscaleStatus {
            installed: true,
            backend_state: "Running".into(),
            self_online: true,
            tailscale_ip: Some("100.64.0.1".into()),
            peers: vec![TailscalePeer {
                name: "node".into(),
                addrs: vec!["100.64.0.2".into()],
                online: true,
                active: false,
                last_seen_seconds_ago: None,
                exit_node: false,
                relay: None,
                rx_bytes: None,
                tx_bytes: None,
            }],
            ..Default::default()
        };
        let bytes = postcard::to_allocvec(&status).unwrap();
        let back: TailscaleStatus = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn wan_identity_defaults_are_safe() {
        let id = WanIdentity::default();
        assert_eq!(id.hardware_mac, None);
        assert!(!id.cloning_active);
        assert_eq!(id.dhcp.dns.len(), 0);
    }
}
