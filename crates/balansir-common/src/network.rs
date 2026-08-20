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
    /// Link speed in Mbps reported by the kernel (netlink `IFLA_INFO_DATA`
    /// ether speed, or sysfs `speed`). `None` for virtual/unknown devices.
    pub speed_mbps: Option<u64>,
    /// Negotiated duplex: `"full"`, `"half"`, or `None` when unknown.
    #[serde(default)]
    pub duplex: Option<String>,
    /// Maximum throughput the adapter can actually achieve, measured in Mbps.
    /// Measured with iperf3 (when available) or the Rust-native probe; the
    /// mission requires a real measurement, not just the advertised link speed.
    #[serde(default)]
    pub max_throughput_mbps: Option<u64>,
    /// Whether the interface is USB-backed (sysfs `device/bus == usb`).
    #[serde(default)]
    pub usb: bool,
    /// Kernel driver bound to the device (sysfs `device/driver`), e.g.
    /// `r8152`, `ax88179_178a`, `mt76x0u`.
    #[serde(default)]
    pub driver: Option<String>,
    /// Physical bus the device sits on: `usb`, `pci`, `platform`, ...
    #[serde(default)]
    pub bus: Option<String>,
    /// Vendor identifier (USB `idVendor` / PCI `vendor`), hex without `0x`.
    #[serde(default)]
    pub vendor_id: Option<String>,
    /// Product identifier (USB `idProduct` / PCI `device`), hex without `0x`.
    #[serde(default)]
    pub product_id: Option<String>,
    /// Human-readable device model/product name (sysfs `device/product` or
    /// USB `product`), e.g. `Realtek USB 2.5GbE Family Controller`.
    #[serde(default)]
    pub device_model: Option<String>,
    /// Interface type (netlink `IFLA_INFO_KIND`), e.g. `wlan`, `ether`.
    #[serde(default)]
    pub if_type: Option<String>,
    /// Wi-Fi link data when this is a wireless interface.
    #[serde(default)]
    pub wifi: Option<WifiInfo>,
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

/// Wi-Fi link information (802.11). Populated for wireless interfaces from
/// `iw`/nl80211 and `/proc/net/wireless`. Never assumes a specific chipset:
/// works for any Linux-compatible adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiInfo {
    /// Whether a wireless device is present behind this interface.
    pub present: bool,
    /// Currently connected SSID (empty when not associated).
    pub ssid: String,
    /// Frequency in MHz of the current channel (0 when not associated).
    pub freq_mhz: u32,
    /// Channel number derived from frequency.
    pub channel: u32,
    /// Signal strength in dBm (0 when unknown).
    pub signal_dbm: i32,
    /// Link quality percentage (0-100).
    pub quality_pct: u8,
    /// Authentication mode when associated: `open`, `wpa2`, `wpa3`, ...
    pub auth: String,
    /// Whether the interface is in AP (hostapd) mode.
    pub ap_mode: bool,
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

/// Wi-Fi connection operation (`MsgType::WifiOp`). The executor is the only
/// component that talks to `iw`/`wpa_supplicant`/`wpa_cli`; the daemon sends a
/// typed request and gets a typed result back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiOp {
    /// Scan for networks on the interface (returns a list of scan results).
    Scan { interface: String },
    /// Connect to a network. `password` may be empty for open networks;
    /// `identity`/`password` for EAP networks. Security mode is auto-detected.
    Connect {
        interface: String,
        ssid: String,
        password: Option<String>,
        identity: Option<String>,
        /// Optional explicit security mode override (`open`/`wpa`/`wpa2`/
        /// `wpa3`/`eap`). When absent, auto-detected from scan results.
        security: Option<String>,
    },
    /// Report association/connection state.
    Status { interface: String },
    /// Disconnect from the current network.
    Disconnect { interface: String },
}

/// Result of a Wi-Fi operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiResult {
    pub ok: bool,
    pub detail: String,
    /// Scan results when the operation was a scan.
    #[serde(default)]
    pub networks: Vec<WifiNetwork>,
}

/// One Wi-Fi network from a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,
    pub signal_dbm: i32,
    pub freq_mhz: u32,
    pub security: String,
    /// Whether this is the currently associated network.
    pub selected: bool,
}

/// MPTCP operation (`MsgType::MptcpOp`). The executor is the only component
/// that touches the kernel MPTCP stack (sysctl + `ip mptcp` netlink); the
/// daemon sends typed requests. Linux kernels ≥ 5.6 have native MPTCP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MptcpOp {
    /// Enable/disable the kernel MPTCP stack (`net.mptcp.enabled`) and report
    /// the resulting state.
    SetEnabled { enabled: bool },
    /// Add an MPTCP local endpoint (`ip mptcp endpoint add <addr> dev <dev>`).
    AddEndpoint {
        /// Local address to advertise as an MPTCP path.
        address: String,
        /// Interface the endpoint binds to (empty = kernel default).
        interface: Option<String>,
    },
    /// Remove a local MPTCP endpoint by address.
    RemoveEndpoint { address: String },
    /// Report MPTCP stack state, endpoints and live subflows.
    Status,
}

/// One MPTCP endpoint / subflow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MptcpEndpoint {
    pub address: String,
    pub iface: String,
    pub local_id: u32,
    /// `subflow` / `signal` / `backup` flags summary.
    pub flags: Vec<String>,
}

/// One live MPTCP subflow (from `/proc/net/mptcp`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MptcpSubflow {
    pub remote: String,
    pub local: String,
    /// TCP state: `ESTABLISHED`, `SYN-SENT`, ...
    pub state: String,
    pub backup: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Result of an MPTCP operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MptcpResult {
    pub ok: bool,
    pub detail: String,
    /// Kernel MPTCP enabled state (after the operation, when known).
    pub enabled: Option<bool>,
    pub endpoints: Vec<MptcpEndpoint>,
    pub subflows: Vec<MptcpSubflow>,
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
    fn wifi_info_default_is_safe() {
        let w = WifiInfo::default();
        assert!(!w.present);
        assert!(w.ssid.is_empty());
        assert_eq!(w.signal_dbm, 0);
    }

    #[test]
    fn interface_info_with_device_fields_roundtrips() {
        let mut info = InterfaceInfo {
            name: "enx1234".into(),
            kind: Some("eth".into()),
            driver: Some("r8152".into()),
            bus: Some("usb".into()),
            vendor_id: Some("0bda".into()),
            product_id: Some("8156".into()),
            device_model: Some("Realtek USB 2.5GbE Family Controller".into()),
            speed_mbps: Some(2500),
            duplex: Some("full".into()),
            max_throughput_mbps: Some(2250),
            usb: true,
            wifi: Some(WifiInfo {
                present: true,
                ssid: "home".into(),
                signal_dbm: -45,
                ..Default::default()
            }),
            ..Default::default()
        };
        info.ipv4.push("192.168.1.10".into());
        let bytes = postcard::to_allocvec(&info).unwrap();
        let back: InterfaceInfo = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back.driver.as_deref(), Some("r8152"));
        assert_eq!(back.speed_mbps, Some(2500));
        assert_eq!(back.max_throughput_mbps, Some(2250));
        assert!(back.usb);
        assert_eq!(back.wifi.as_ref().unwrap().ssid, "home");
        assert_eq!(back.ipv4, vec!["192.168.1.10"]);
    }

    #[test]
    fn wifi_op_roundtrips() {
        let op = WifiOp::Connect {
            interface: "wlan0".into(),
            ssid: "guest".into(),
            password: Some("secret".into()),
            identity: None,
            security: Some("wpa2".into()),
        };
        let bytes = postcard::to_allocvec(&op).unwrap();
        let back: WifiOp = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(
            back,
            WifiOp::Connect {
                interface: "wlan0".into(),
                ssid: "guest".into(),
                password: Some("secret".into()),
                identity: None,
                security: Some("wpa2".into()),
            }
        );
    }

    #[test]
    fn mptcp_op_roundtrips() {
        let op = MptcpOp::AddEndpoint {
            address: "192.168.1.5".into(),
            interface: Some("eth0".into()),
        };
        let bytes = postcard::to_allocvec(&op).unwrap();
        let back: MptcpOp = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, op);

        let result = MptcpResult {
            ok: true,
            detail: "ok".into(),
            enabled: Some(true),
            endpoints: vec![MptcpEndpoint {
                address: "192.168.1.5".into(),
                iface: "eth0".into(),
                local_id: 1,
                flags: vec!["signal".into()],
            }],
            subflows: vec![MptcpSubflow {
                remote: "10.0.0.1:443".into(),
                local: "192.168.1.5:12345".into(),
                state: "ESTABLISHED".into(),
                backup: false,
                rx_bytes: 100,
                tx_bytes: 200,
            }],
        };
        let bytes = postcard::to_allocvec(&result).unwrap();
        let back: MptcpResult = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, result);
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
