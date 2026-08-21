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
#[cfg(target_os = "linux")]
use futures::TryStreamExt;
#[cfg(target_os = "linux")]
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
    let parts: Vec<&str> = cleaned
        .split([':', '-'])
        .filter(|p| !p.is_empty())
        .collect();
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

#[cfg(target_os = "linux")]
/// Real netlink-backed interface driver.
#[cfg(target_os = "linux")]
pub struct NetlinkInterfaceBackend {
    handle: tokio::sync::Mutex<rtnetlink::Handle>,
}

#[cfg(target_os = "linux")]
impl NetlinkInterfaceBackend {
    pub async fn new() -> Result<Self, String> {
        let (connection, handle, _events) =
            rtnetlink::new_connection().map_err(|e| format!("netlink connection failed: {e}"))?;
        tokio::spawn(connection);
        Ok(Self {
            handle: tokio::sync::Mutex::new(handle),
        })
    }

    /// Dump all links matching the filter.
    async fn dump_links(
        &self,
        name: &str,
    ) -> Result<Vec<(LinkHeader, Vec<LinkAttribute>)>, String> {
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

    /// Dump all IPv4/IPv6 addresses on an interface (RTM_GETADDR). Returns a
    /// map of interface index → list of "ip/prefix" strings.
    async fn dump_addresses(&self, ifindex: u32) -> Result<Vec<String>, String> {
        let handle = self.handle.lock().await;
        let mut req = handle.address().get().execute();
        let mut out = Vec::new();
        while let Some(addr) = req.try_next().await.map_err(|e| e.to_string())? {
            let attrs = addr.attributes;
            if addr.header.index != ifindex {
                continue;
            }
            let Some(addr_bytes) = attrs.iter().find_map(|a| match a {
                netlink_packet_route::address::AddressAttribute::Address(b) => Some(b),
                _ => None,
            }) else {
                continue;
            };
            let prefix = addr.header.prefix_len;
            match addr_bytes {
                std::net::IpAddr::V4(v4) => {
                    let o = v4.octets();
                    out.push(format!("{}.{}.{}.{}/{}", o[0], o[1], o[2], o[3], prefix));
                }
                std::net::IpAddr::V6(v6) => {
                    out.push(format!("{}/{}", v6, prefix));
                }
            }
        }
        Ok(out)
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

    /// The MAC currently in effect for an interface (for restore fallback).
    async fn current_mac(&self, name: &str) -> Option<String> {
        let links = self.dump_links(name).await.ok()?;
        for (_, attrs) in links {
            for attr in attrs {
                if let LinkAttribute::Address(bytes) = attr {
                    if let Some(mac) = format_mac(&bytes) {
                        return Some(mac);
                    }
                }
            }
        }
        None
    }
}

/// Format an IPv6 byte array as `2001:db8::1`.
#[cfg(target_os = "linux")]
pub fn ipv6_to_string(bytes: &[u8]) -> String {
    use std::net::Ipv6Addr;
    let mut octets = [0u8; 16];
    octets.copy_from_slice(bytes);
    Ipv6Addr::from(octets).to_string()
}

/// Fill device identity fields (driver/bus/vendor/product/model, USB flag,
/// Wi-Fi info) from sysfs. `/sys/class/net/<name>/device/` is a symlink to the
/// PCI/USB device node; the real adapter model is found one level up (the
/// USB interface → the USB device).
#[cfg(target_os = "linux")]
fn enrich_device_info(name: &str, info: &mut InterfaceInfo) {
    let base = format!("/sys/class/net/{name}");
    let read = |p: &str| -> Option<String> {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
    };
    let device = format!("{base}/device");
    let driver = format!("{device}/driver");

    // Driver: the symlink target of .../device/driver (last path component).
    if let Ok(target) = std::fs::read_link(&driver) {
        info.driver = target.file_name().map(|s| s.to_string_lossy().to_string());
    }
    // USB devices carry idVendor/idProduct/ manufacturer/product at the USB
    // device level (../../idVendor from the interface node).
    let dev_uevent = read(&format!("{device}/uevent"));
    if let Some(uevent) = dev_uevent {
        for line in uevent.lines() {
            if let Some((k, v)) = line.split_once('=') {
                match k {
                    "PCI_ID" => {
                        let mut parts = v.split(':');
                        info.vendor_id = parts.next().map(|s| s.to_string());
                        info.product_id = parts.next().map(|s| s.to_string());
                    }
                    "USB_ID" => {
                        let mut parts = v.split(':');
                        info.vendor_id = parts.next().map(|s| s.to_string());
                        info.product_id = parts.next().map(|s| s.to_string());
                    }
                    "DEVTYPE" => {}
                    "DRIVER" => {
                        if info.driver.is_none() {
                            info.driver = Some(v.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    // The USB bus is where idVendor/idProduct/product live; walk up to the
    // USB device node (the net device sits under the USB interface).
    let mut probe = std::path::PathBuf::from(&device);
    for _ in 0..4 {
        let vid = read(&probe.join("idVendor"));
        let pid = read(&probe.join("idProduct"));
        let product = read(&probe.join("product"));
        let manufacturer = read(&probe.join("manufacturer"));
        if vid.is_some() || pid.is_some() {
            info.vendor_id = vid.or(info.vendor_id);
            info.product_id = pid.or(info.product_id);
            if product.is_some() {
                info.device_model = product;
            } else {
                info.device_model = info.device_model.or(manufacturer);
            }
            info.usb = true;
            info.bus = Some("usb".into());
            break;
        }
        // Walk one level up (USB interface → USB device).
        let Some(parent) = probe.parent() else { break };
        probe = parent.to_path_buf();
    }
    if info.bus.is_none() {
        info.bus = read(&format!("{device}/bus"))
            .and_then(|p| p.rsplit('/').next().map(|s| s.to_string()));
    }
    // PCI devices report vendor/device at the device node itself.
    if info.vendor_id.is_none() {
        info.vendor_id = read(&format!("{device}/vendor"))
            .and_then(|s| s.strip_prefix("0x").map(|s| s.to_string()));
        info.product_id = read(&format!("{device}/device"))
            .and_then(|s| s.strip_prefix("0x").map(|s| s.to_string()));
    }
    // Wi-Fi presence: netlink kind reports wlan/wifi; also check the wireless
    // sysfs dir (present on 802.11 devices) and /proc/net/wireless.
    if info
        .kind
        .as_deref()
        .map(|k| k.contains("wlan") || k == "wifi")
        .unwrap_or(false)
        || std::path::Path::new(&format!("{base}/wireless")).exists()
    {
        info.wifi = Some(read_wifi_state(name));
    }
}

/// Read Wi-Fi state from `/proc/net/wireless` + sysfs for one interface.
#[cfg(target_os = "linux")]
fn read_wifi_state(name: &str) -> balansir_common::network::WifiInfo {
    use balansir_common::network::WifiInfo;
    let mut info = WifiInfo {
        present: true,
        ..Default::default()
    };
    let base = format!("/sys/class/net/{name}");
    if let Ok(w) = std::fs::read_to_string(format!("{base}/wireless")) {
        let mut lines = w.lines();
        let _ = lines.next(); // header
        let _ = lines.next(); // separator
        if let Some(line) = lines.next() {
            // Interface name, status, link(%), level(dBm), noise(dBm), discarded counters
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 4 {
                if let Ok(link) = fields[2].trim_end_matches('.').parse::<u8>() {
                    info.quality_pct = link;
                }
                if let Ok(level) = fields[3].trim_end_matches('.').parse::<i32>() {
                    info.signal_dbm = level;
                }
            }
        }
    }
    // ssid via `iw` is a shell call; the daemon's Wi-Fi manager reports it
    // through WifiOp::Status instead. Here we only surface presence/link.
    info
}

#[cfg(target_os = "linux")]
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
            // The permanent factory MAC is the WAN-identity anchor and is
            // never overwritten by cloning. It is *not* the current MAC when
            // cloning is active.
            LinkAttribute::PermAddress(bytes) => {
                if let Some(mac) = format_mac(&bytes) {
                    info.hardware_mac = Some(mac.clone());
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
                        info.if_type = Some(kind.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    enrich_device_info(&info.name, &mut info);
    info
}

/// Fill link speed (Mbps) and duplex from sysfs. `/sys/class/net/<name>/speed`
/// holds the negotiated link speed in Mbps (`-1` = unknown), and `duplex` is
/// `full`/`half`. Also fills device identity fields when missing.
#[cfg(target_os = "linux")]
fn fill_speed_duplex(info: &mut InterfaceInfo) {
    let base = format!("/sys/class/net/{}", info.name);
    if let Ok(s) = std::fs::read_to_string(format!("{base}/speed")) {
        if let Ok(speed) = s.trim().parse::<i64>() {
            if speed > 0 {
                info.speed_mbps = Some(speed as u64);
            }
        }
    }
    if let Ok(d) = std::fs::read_to_string(format!("{base}/duplex")) {
        let d = d.trim().to_string();
        if d == "full" || d == "half" {
            info.duplex = Some(d);
        }
    }
}

#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
impl InterfaceBackend for NetlinkInterfaceBackend {
    async fn info(&self, interface: &str) -> Result<Vec<InterfaceInfo>, String> {
        let links = self.dump_links(interface).await?;
        let mut out = Vec::new();
        for (header, attrs) in links {
            let name = attrs
                .iter()
                .find_map(|a| match a {
                    LinkAttribute::IfName(n) => Some(n.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| format!("link{}", header.index));
            let mut info = link_to_info(name, header, attrs);
            info.previous_mac = remembered_previous_mac(&info.name);
            // Addresses (RTM_GETADDR) — separate netlink dump.
            if let Ok(addrs) = self.dump_addresses(info.index as u32).await {
                for a in addrs {
                    if a.contains(':') {
                        info.ipv6.push(a);
                    } else {
                        info.ipv4.push(a);
                    }
                }
            }
            // Speed + duplex from sysfs (kernel exposes IFLA_INFO_DATA ether
            // speed in netlink-packet-route's LinkInfo, but the value is also
            // available via sysfs which is simpler and works for any device).
            fill_speed_duplex(&mut info);
            out.push(info);
        }
        Ok(out)
    }

    async fn set_mac(&self, interface: &str, mac: &str) -> Result<InterfaceResult, String> {
        let mac = validate_mac(mac).ok_or_else(|| format!("invalid MAC address: {mac}"))?;
        let hardware = self.permanent_mac(interface).await;
        // Capture the MAC in effect *before* the clone so restore can fall back
        // to it when no permanent hardware address exists (virtual WAN
        // interfaces). The factory MAC is never overwritten on-disk.
        let previous = self.current_mac(interface).await;
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
        if let Some(prev) = &previous {
            remember_previous_mac(interface, prev);
        }
        Ok(InterfaceResult {
            ok: true,
            detail: format!("MAC cloned to {mac}"),
            hardware_mac: hardware.clone(),
            current_mac: Some(mac),
            previous_mac: previous,
        })
    }

    async fn restore_mac(&self, interface: &str) -> Result<InterfaceResult, String> {
        // Prefer the permanent factory MAC; fall back to the MAC remembered
        // before the last clone (so restore works even when the kernel exposes
        // no IFLA_PERM_ADDRESS). The factory MAC is authoritative when present.
        // NB: capture `hardware` up front — the netlink handle mutex is not
        // reentrant, so a second dump after locking it would deadlock.
        let hardware = self.permanent_mac(interface).await;
        let target = hardware
            .clone()
            .or_else(|| remembered_previous_mac(interface))
            .ok_or_else(|| format!("no permanent hardware MAC available for {interface}"))?;
        let index = self.find_index(interface).await?;
        let handle = self.handle.lock().await;
        let bytes: Vec<u8> = target
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
        drop(handle);
        // Once restored to the factory MAC, the remembered clone source is no
        // longer needed.
        if hardware.is_some() {
            forget_previous_mac(interface);
        }
        Ok(InterfaceResult {
            ok: true,
            detail: format!("MAC restored to factory {target}"),
            hardware_mac: hardware,
            current_mac: Some(target),
            previous_mac: None,
        })
    }
}

/// Root-owned state file mapping interface → the MAC that was in effect before
/// the last clone. Written atomically, mode 0600; this is the *fallback* for
/// restore when a permanent hardware MAC does not exist — never the factory MAC
/// itself.
#[cfg(target_os = "linux")]
const MAC_STATE_PATH: &str = "/run/balansir/mac-state.json";

#[cfg(target_os = "linux")]
fn remember_previous_mac(interface: &str, mac: &str) {
    remember_previous_mac_at(std::path::Path::new(MAC_STATE_PATH), interface, mac);
}

#[cfg(target_os = "linux")]
fn remembered_previous_mac(interface: &str) -> Option<String> {
    remembered_previous_mac_at(std::path::Path::new(MAC_STATE_PATH), interface)
}

#[cfg(target_os = "linux")]
fn forget_previous_mac(interface: &str) {
    forget_previous_mac_at(std::path::Path::new(MAC_STATE_PATH), interface);
}

#[cfg(target_os = "linux")]
fn remember_previous_mac_at(path: &std::path::Path, interface: &str, mac: &str) {
    let mut map = read_mac_state_at(path).unwrap_or_default();
    map.insert(interface.to_string(), mac.to_string());
    write_mac_state_at(path, &map);
}

#[cfg(target_os = "linux")]
fn remembered_previous_mac_at(path: &std::path::Path, interface: &str) -> Option<String> {
    read_mac_state_at(path)
        .ok()
        .and_then(|m| m.get(interface).cloned())
}

#[cfg(target_os = "linux")]
fn forget_previous_mac_at(path: &std::path::Path, interface: &str) {
    let mut map = read_mac_state_at(path).unwrap_or_default();
    if map.remove(interface).is_some() {
        write_mac_state_at(path, &map);
    }
}

#[cfg(target_os = "linux")]
fn read_mac_state_at(
    path: &std::path::Path,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&content).map_err(|e| format!("parse {}: {e}", path.display()))
}

#[cfg(target_os = "linux")]
fn write_mac_state_at(path: &std::path::Path, map: &std::collections::BTreeMap<String, String>) {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp, serde_json::to_string(map).unwrap_or_default()) {
        tracing::warn!(path = %tmp.display(), "write mac state: {e}");
        return;
    }
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    if let Err(e) = std::fs::rename(&tmp, path) {
        tracing::warn!(path = %path.display(), "commit mac state: {e}");
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
                index: read_str("ifindex")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn mac_formatting() {
        assert_eq!(
            format_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            Some("aa:bb:cc:dd:ee:ff".into())
        );
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
        assert_eq!(
            validate_mac("01:bb:cc:dd:ee:ff"),
            None,
            "multicast rejected"
        );
        assert_eq!(validate_mac("aa:bb:cc:dd:ee:ff:00"), None);
    }

    #[test]
    fn previous_mac_state_round_trip() {
        let dir = std::env::temp_dir().join(format!("balansir-mac-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mac-state.json");

        // Unknown interfaces are not remembered.
        assert_eq!(remembered_previous_mac_at(&path, "wan0"), None);

        // Clone remembers the pre-clone MAC.
        remember_previous_mac_at(&path, "wan0", "00:11:22:33:44:55");
        assert_eq!(
            remembered_previous_mac_at(&path, "wan0"),
            Some("00:11:22:33:44:55".into())
        );
        // Different interfaces do not collide.
        assert_eq!(remembered_previous_mac_at(&path, "lan0"), None);

        // A second clone overwrites the remembered pre-clone MAC.
        remember_previous_mac_at(&path, "wan0", "00:11:22:33:44:66");
        assert_eq!(
            remembered_previous_mac_at(&path, "wan0"),
            Some("00:11:22:33:44:66".into())
        );

        // Restore to factory forgets the entry.
        forget_previous_mac_at(&path, "wan0");
        assert_eq!(remembered_previous_mac_at(&path, "wan0"), None);

        std::fs::remove_dir_all(&dir).ok();
    }
}
