//! Interface driver: link information and WAN MAC cloning.
//!
//! This is the executor-side privileged mechanism for network interface
//! introspection and MAC identity management. All operations use netlink
//! (`rtnetlink`); no shell commands are involved.
//!
//! WAN identity safety: the kernel exposes the permanent factory MAC via
//! `IFLA_PERM_ADDRESS`; the executor always reads it *before* any change and
//! uses it for `RestoreMac`. The original hardware MAC is never overwritten
//! permanently — a cloned MAC is a reversible, kernel-level change.

use async_trait::async_trait;
use balansir_common::network::{InterfaceInfo, InterfaceResult};
use futures::TryStreamExt;
use netlink_packet_route::link::{LinkAttribute, LinkHeader, State, Stats64};

/// Format raw MAC bytes as `aa:bb:cc:dd:ee:ff`.
pub fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Validate a MAC address string; returns canonical lowercase form.
pub fn validate_mac(input: &str) -> Option<String> {
    let cleaned: String = input
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || *c == ':' || *c == '-')
        .collect();
    let parts: Vec<&str> = cleaned.split([':', '-']).filter(|p| !p.is_empty()).collect();
    if parts.len() != 6 || parts.iter().any(|p| p.len() > 2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = parts
        .iter()
        .map(|p| u8::from_str_radix(p, 16).ok())
        .collect();
    let bytes = bytes?;
    if bytes[0] & 0x01 != 0 {
        return None; // multicast MACs are invalid for an interface
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// The privileged interface mechanism.
#[async_trait]
pub trait InterfaceBackend: Send + Sync {
    /// Read link info for one interface (empty name = all interfaces).
    async fn info(&self, interface: &str) -> Result<Vec<InterfaceInfo>, String>;
    /// Set the interface MAC (clone). Returns the hardware MAC for safety.
    async fn set_mac(&self, interface: &str, mac: &str) -> Result<InterfaceResult, String>;
    /// Restore the factory MAC.
    async fn restore_mac(&self, interface: &str) -> Result<InterfaceResult, String>;
}

/// Real netlink-backed interface driver.
pub struct NetlinkInterfaceBackend {
    handle: tokio::sync::Mutex<rtnetlink::Handle>,
}

impl NetlinkInterfaceBackend {
    pub async fn new() -> Result<Self, String> {
        let (connection, handle, _events) = rtnetlink::new_connection()
            .map_err(|e| format!("netlink connection failed: {e}"))?;
        tokio::spawn(connection);
        Ok(Self {
            handle: tokio::sync::Mutex::new(handle),
        })
    }

    /// Dump all links matching the filter.
    async fn dump_links(&self, name: &str) -> Result<Vec<(LinkHeader, Vec<LinkAttribute>)>, String> {
        let handle = self.handle.lock().await;
        let mut req = handle.link().get();
        if !name.is_empty() {
            req = req.match_name(name.to_string());
        }
        let mut stream = req.execute();
        let mut links = Vec::new();
        while let Some(link) = stream.try_next().await.map_err(|e| e.to_string())? {
            links.push((link.header, link.attributes));
        }
        Ok(links)
    }

    async fn find_index(&self, name: &str) -> Result<u32, String> {
        let links = self.dump_links(name).await?;
        links
            .into_iter()
            .next()
            .map(|(h, _)| h.index)
            .ok_or_else(|| format!("interface {name} not found"))
    }

    /// The permanent factory MAC (`IFLA_PERM_ADDRESS`) for an interface.
    async fn permanent_mac(&self, name: &str) -> Option<String> {
        let links = self.dump_links(name).await.ok()?;
        for (_, attrs) in links {
            for attr in attrs {
                if let LinkAttribute::PermAddress(bytes) = attr {
                    if let Some(mac) = format_mac(&bytes) {
                        return Some(mac);
                    }
                }
            }
        }
        None
    }
}

fn link_to_info(name: String, header: LinkHeader, attrs: Vec<LinkAttribute>) -> InterfaceInfo {
    let mut info = InterfaceInfo {
        name,
        index: header.index as i32,
        ..Default::default()
    };
    for attr in attrs {
        match attr {
            LinkAttribute::Address(bytes) => {
                if info.mac.is_none() {
                    info.mac = format_mac(&bytes);
                }
            }
            LinkAttribute::PermAddress(bytes) => {
                if let Some(mac) = format_mac(&bytes) {
                    if info.mac.is_none() {
                        info.mac = Some(mac);
                    }
                }
            }
            LinkAttribute::IfName(name) => info.name = name,
            LinkAttribute::Mtu(mtu) => info.mtu = mtu,
            LinkAttribute::OperState(state) => {
                info.oper_state = Some(match state {
                    State::Up => "up".to_string(),
                    State::Down => "down".to_string(),
                    State::LowerLayerDown => "lowerlayerdown".to_string(),
                    State::Unknown => "unknown".to_string(),
                    State::NotPresent => "notpresent".to_string(),
                    State::Testing => "testing".to_string(),
                    State::Dormant => "dormant".to_string(),
                    State::Other(v) => format!("state-{v}"),
                    _ => "unknown".into(),
                });
                info.link_up = matches!(state, State::Up);
            }
            LinkAttribute::Carrier(carrier) => {
                if carrier == 0 {
                    info.link_up = false;
                }
            }
            LinkAttribute::Stats64(s) => apply_stats64(&mut info, s),
            LinkAttribute::Stats(s) => {
                if info.rx_bytes == 0 {
                    info.rx_bytes = s.rx_bytes as u64;
                    info.tx_bytes = s.tx_bytes as u64;
                    info.rx_packets = s.rx_packets as u64;
                    info.tx_packets = s.tx_packets as u64;
                    info.rx_errors = s.rx_errors as u64;
                    info.tx_errors = s.tx_errors as u64;
                    info.rx_dropped = s.rx_dropped as u64;
                    info.tx_dropped = s.tx_dropped as u64;
                    info.multicast = s.multicast as u64;
                }
            }
            LinkAttribute::Qdisc(qdisc) => info.qdisc = Some(qdisc),
            LinkAttribute::LinkInfo(infos) => {
                for li in infos {
                    if let netlink_packet_route::link::LinkInfo::Kind(kind) = li {
                        info.kind = Some(kind.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    info
}

fn apply_stats64(info: &mut InterfaceInfo, s: Stats64) {
    info.rx_bytes = s.rx_bytes;
    info.tx_bytes = s.tx_bytes;
    info.rx_packets = s.rx_packets;
    info.tx_packets = s.tx_packets;
    info.rx_errors = s.rx_errors;
    info.tx_errors = s.tx_errors;
    info.rx_dropped = s.rx_dropped;
    info.tx_dropped = s.tx_dropped;
    info.multicast = s.multicast;
}

#[async_trait]
impl InterfaceBackend for NetlinkInterfaceBackend {
    async fn info(&self, interface: &str) -> Result<Vec<InterfaceInfo>, String> {
        let links = self.dump_links(interface).await?;
        Ok(links
            .into_iter()
            .map(|(header, attrs)| {
                let name = attrs
                    .iter()
                    .find_map(|a| match a {
                        LinkAttribute::IfName(n) => Some(n.clone()),
                        _ => None,
                    })
                    .unwrap_or_else(|| format!("link{}", header.index));
                link_to_info(name, header, attrs)
            })
            .collect())
    }

    async fn set_mac(&self, interface: &str, mac: &str) -> Result<InterfaceResult, String> {
        let mac = validate_mac(mac).ok_or_else(|| format!("invalid MAC address: {mac}"))?;
        let hardware = self.permanent_mac(interface).await;
        let index = self.find_index(interface).await?;
        let handle = self.handle.lock().await;
        let bytes: Vec<u8> = mac
            .split(':')
            .filter_map(|p| u8::from_str_radix(p, 16).ok())
            .collect();
        handle
            .link()
            .set(index)
            .address(bytes)
            .execute()
            .await
            .map_err(|e| format!("set MAC {interface}: {e}"))?;
        Ok(InterfaceResult {
            ok: true,
            detail: format!("MAC cloned to {mac}"),
            hardware_mac: hardware.clone(),
            current_mac: Some(mac),
        })
    }

    async fn restore_mac(&self, interface: &str) -> Result<InterfaceResult, String> {
        let hardware = self.permanent_mac(interface).await;
        let Some(hardware) = hardware else {
            return Err(format!(
                "no permanent hardware MAC available for {interface}"
            ));
        };
        let index = self.find_index(interface).await?;
        let handle = self.handle.lock().await;
        let bytes: Vec<u8> = hardware
            .split(':')
            .filter_map(|p| u8::from_str_radix(p, 16).ok())
            .collect();
        handle
            .link()
            .set(index)
            .address(bytes)
            .execute()
            .await
            .map_err(|e| format!("restore MAC {interface}: {e}"))?;
        Ok(InterfaceResult {
            ok: true,
            detail: format!("MAC restored to factory {hardware}"),
            hardware_mac: Some(hardware.clone()),
            current_mac: Some(hardware),
        })
    }
}

/// Record-only backend used when no privileged netlink mechanism is available.
/// Reports interface info from `/sys` (read-only) but refuses MAC changes.
pub struct SysfsInterfaceBackend;

#[async_trait]
impl InterfaceBackend for SysfsInterfaceBackend {
    async fn info(&self, interface: &str) -> Result<Vec<InterfaceInfo>, String> {
        let names: Vec<String> = if interface.is_empty() {
            std::fs::read_dir("/sys/class/net")
                .map_err(|e| e.to_string())?
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        } else {
            vec![interface.to_string()]
        };
        let mut out = Vec::new();
        for name in names {
            let base = format!("/sys/class/net/{name}");
            let read_str = |field: &str| -> Option<String> {
                std::fs::read_to_string(format!("{base}/{field}"))
                    .ok()
                    .map(|s| s.trim().to_string())
            };
            out.push(InterfaceInfo {
                name,
                index: read_str("ifindex").and_then(|s| s.parse().ok()).unwrap_or(0),
                kind: read_str("uevent").and_then(|u| {
                    u.lines()
                        .find(|l| l.starts_with("DEVTYPE="))
                        .map(|l| l.trim_start_matches("DEVTYPE=").to_string())
                }),
                mac: read_str("address"),
                link_up: read_str("operstate").as_deref() == Some("up"),
                mtu: read_str("mtu").and_then(|s| s.parse().ok()).unwrap_or(0),
                oper_state: read_str("operstate"),
                ..Default::default()
            });
        }
        Ok(out)
    }

    async fn set_mac(&self, _interface: &str, _mac: &str) -> Result<InterfaceResult, String> {
        Err("MAC changes require a privileged netlink backend".into())
    }

    async fn restore_mac(&self, _interface: &str) -> Result<InterfaceResult, String> {
        Err("MAC changes require a privileged netlink backend".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_formatting() {
        assert_eq!(format_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), Some("aa:bb:cc:dd:ee:ff".into()));
        assert_eq!(format_mac(&[0x01]), None);
    }

    #[test]
    fn mac_validation() {
        assert_eq!(
            validate_mac("AA:BB:CC:DD:EE:FF"),
            Some("aa:bb:cc:dd:ee:ff".into())
        );
        assert_eq!(
            validate_mac("aa-bb-cc-dd-ee-ff"),
            Some("aa:bb:cc:dd:ee:ff".into())
        );
        assert_eq!(validate_mac("zz:bb:cc:dd:ee:ff"), None);
        assert_eq!(validate_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(validate_mac("01:bb:cc:dd:ee:ff"), None, "multicast rejected");
        assert_eq!(validate_mac("aa:bb:cc:dd:ee:ff:00"), None);
    }
}
