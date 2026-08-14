//! WAN identity assembly (mission §13).
//!
//! The WAN identity answers "how does this device present itself to the ISP?"
//! — factory vs. current MAC (cloning), MTU, link state, and the DHCP/route
//! observation. The interface list comes from the executor (netlink); the
//! default-route / DHCP observation comes from the host stack. No new
//! privileged path: everything here is read-only host-stack inspection.

use balansir_common::network::{InterfaceInfo, WanDhcpState, WanIdentity};

/// The WAN interface name, or `None` when the operator has not pinned one and
/// no default route is present.
///
/// Selection order:
/// 1. `BALANSIR_WAN_INTERFACE` (operator override; also used by tests);
/// 2. the interface owning the IPv4 default route (`/proc/net/route`).
pub fn detect_wan_interface(env_override: Option<&str>) -> Option<String> {
    if let Some(name) = env_override {
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    default_route_interface()
}

/// Name of the interface that owns the IPv4 default route.
pub fn default_route_interface() -> Option<String> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        // Destination (hex) and the route flags. Destination `00000000` is the
        // default route; flag bit 0x2 (RTF_GATEWAY) marks a gateway route.
        if fields[1] == "00000000" {
            return Some(fields[0].to_string());
        }
    }
    None
}

/// Default-route gateway IP for the given interface (from `/proc/net/route`).
fn default_route_gateway(interface: &str) -> Option<String> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 || fields[0] != interface || fields[1] != "00000000" {
            continue;
        }
        return Some(hex_le_to_ipv4(fields[2])?);
    }
    None
}

/// Convert a little-endian hex IPv4 (as printed by `/proc/net/route`) to an
/// `a.b.c.d` string.
fn hex_le_to_ipv4(hex: &str) -> Option<String> {
    let value = u32::from_str_radix(hex, 16).ok()?;
    let octets = value.to_le_bytes();
    Some(format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]))
}

/// Assemble the WAN identity for the current interface snapshot.
pub fn assemble(interfaces: &[InterfaceInfo], env_override: Option<&str>) -> Option<WanIdentity> {
    let interface = detect_wan_interface(env_override)?;
    let info = interfaces.iter().find(|i| i.name == interface)?;

    let hardware_mac = info.hardware_mac.clone().or_else(|| info.mac.clone());
    let current_mac = info.mac.clone();
    // Cloning is active when the current MAC differs from the factory MAC.
    let cloning_active = match (&hardware_mac, &current_mac) {
        (Some(hw), Some(cur)) => hw != cur,
        _ => false,
    };

    let gateway = default_route_gateway(&interface);
    let dhcp = WanDhcpState {
        observed: gateway.is_some() || !info.ipv4.is_empty(),
        ip: info.ipv4.first().cloned(),
        gateway,
        dns: Vec::new(),
        lease_seconds: None,
        hostname: None,
    };

    let configured_mac = if cloning_active { current_mac.clone() } else { None };
    Some(WanIdentity {
        interface,
        hardware_mac,
        current_mac,
        configured_mac,
        cloning_active,
        mtu: info.mtu,
        link_up: info.link_up,
        dhcp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_le_ipv4_roundtrip() {
        assert_eq!(hex_le_to_ipv4("0101A8C0"), Some("192.168.1.1".into()));
        assert_eq!(hex_le_to_ipv4("00000000"), Some("0.0.0.0".into()));
        assert_eq!(hex_le_to_ipv4("zz"), None);
    }

    #[test]
    fn route_parse_is_resilient_to_garbage() {
        // Must never panic regardless of host route state. On a host without a
        // default route both are None; on a routed host they are Some — the
        // invariant is that parsing never fails.
        let _ = default_route_interface();
        let _ = default_route_gateway("definitely-not-an-interface");
        // A non-existent interface never yields a gateway.
        assert_eq!(default_route_gateway("eth-definitely-absent-xyz"), None);
    }

    #[test]
    fn assemble_identity() {
        let info = InterfaceInfo {
            name: "eth0".into(),
            index: 2,
            kind: Some("eth".into()),
            mac: Some("02:00:00:00:00:99".into()),
            hardware_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            mtu: 1500,
            link_up: true,
            ipv4: vec!["192.168.1.2".into()],
            ..Default::default()
        };
        let id = assemble(&[info], Some("eth0")).expect("wan identity");
        assert_eq!(id.interface, "eth0");
        assert_eq!(id.hardware_mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(id.current_mac.as_deref(), Some("02:00:00:00:00:99"));
        assert!(id.cloning_active);
        assert_eq!(id.configured_mac.as_deref(), Some("02:00:00:00:00:99"));
        assert!(id.dhcp.observed);
    }

    #[test]
    fn no_cloning_when_macs_match() {
        let info = InterfaceInfo {
            name: "eth0".into(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            hardware_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            ..Default::default()
        };
        let id = assemble(&[info], Some("eth0")).expect("wan identity");
        assert!(!id.cloning_active);
        assert_eq!(id.configured_mac, None);
    }

    #[test]
    fn unknown_interface_yields_none() {
        let info = InterfaceInfo {
            name: "lan0".into(),
            ..Default::default()
        };
        assert!(assemble(&[info], Some("wan0")).is_none());
    }
}
