//! Minimal UPnP Internet Gateway Device (IGD) control point.
//!
//! The daemon runs the IGD: an SSDP M-SEARCH responder on the LAN plus an
//! HTTP/SOAP control endpoint (`AddPortMapping`/`DeletePortMapping`/
//! `GetExternalIPAddress`/`GetSpecificPortMappingEntry`). When a LAN client
//! requests a port mapping, the daemon installs a DNAT rule in the privileged
//! executor's `nat prerouting` chain — the daemon never touches netfilter
//! itself (single nftables owner guarantee, ADR-013).
//!
//! Security posture:
//! - SSDP + control HTTP only reachable from the LAN subnet (source-address
//!   checked against `NetworkConfig::lan_subnet`); WAN UPnP is blocked.
//! - Mappings are validated: port 0 rejected, internal target must be a
//!   unicast non-loopback address, only TCP/UDP supported.
//! - Mappings carry a lease (`NewLeaseDuration`, 0 = permanent); expired
//!   mappings are removed and their DNAT rule deleted.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, warn};

use crate::reconciliation::executor_client::ExecutorClient;

const USN_UUID: &str = "8b1a3a62-3f2c-4a7e-9b6c-d0e1f2a3b4c5";
const DEVICE_TYPE: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
const SERVICE_TYPE: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

/// A single active port mapping (lease-aware).
#[derive(Debug, Clone)]
pub struct PortMapping {
    pub external_port: u16,
    pub proto: String,
    pub internal_ip: IpAddr,
    pub internal_port: u16,
    /// Lease in seconds; `None` = permanent (`NewLeaseDuration` 0).
    pub expires_at: Option<Instant>,
}

/// LAN IP of the IGD (advertised in SSDP `LOCATION` and used to bind the
/// control HTTP listener).
#[derive(Debug, Clone)]
struct IgdAddr {
    ip: IpAddr,
    port: u16,
}

impl IgdAddr {
    fn location(&self) -> String {
        format!("http://{}:{}/rootDesc.xml", self.ip, self.port)
    }
}

/// Runs the UPnP IGD: SSDP responder + SOAP control point, applying DNAT
/// mappings through the executor.
pub struct UpnpManager {
    executor: Option<Arc<ExecutorClient>>,
    lan_subnet: String,
    wan_interface: String,
    /// Bind address of the control listener.
    addr: IgdAddr,
    mappings: std::sync::Mutex<HashMap<(u16, String), PortMapping>>,
}

impl UpnpManager {
    /// Bind the IGD to the given LAN IP and control port.
    pub fn new(
        executor: Option<Arc<ExecutorClient>>,
        lan_ip: IpAddr,
        lan_subnet: &str,
        wan_interface: &str,
        control_port: u16,
    ) -> Self {
        Self {
            executor,
            lan_subnet: lan_subnet.to_string(),
            wan_interface: wan_interface.to_string(),
            addr: IgdAddr {
                ip: lan_ip,
                port: control_port,
            },
            mappings: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Start the IGD: SSDP responder (UDP, LAN-only) and the SOAP control
    /// HTTP endpoint (TCP, LAN-only). Runs forever on failure-free paths.
    pub async fn run(self: &Arc<Self>) {
        // UDP SSDP responder: join the LAN multicast group.
        let udp = match UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 1900))).await {
            Ok(sock) => match sock
                .join_multicast_v4([239, 255, 255, 250].into(), self.multicast_interface())
            {
                Ok(()) => Some(sock),
                Err(e) => {
                    warn!("UPnP: cannot join SSDP multicast group: {e} (SSDP disabled)");
                    None
                }
            },
            Err(e) => {
                warn!("UPnP: cannot bind SSDP port 1900: {e} (SSDP disabled)");
                None
            }
        };

        let tcp = match TcpListener::bind(SocketAddr::from((self.addr.ip, self.addr.port))).await {
            Ok(listener) => Some(listener),
            Err(e) => {
                warn!(
                    "UPnP: cannot bind control listener {}:{}: {e}",
                    self.addr.ip, self.addr.port
                );
                None
            }
        };

        let ssdp_me = Arc::clone(self);
        if let Some(sock) = udp {
            tokio::spawn(async move { ssdp_me.serve_ssdp(sock).await });
        }
        let ctl_me = Arc::clone(self);
        if let Some(listener) = tcp {
            tokio::spawn(async move { ctl_me.serve_control(listener).await });
        }

        self.expiry_loop().await;
    }

    fn multicast_interface(&self) -> std::net::Ipv4Addr {
        // Bind the SSDP socket to the LAN IP (join on the LAN interface).
        match self.addr.ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => std::net::Ipv4Addr::UNSPECIFIED,
        }
    }

    /// SSDP M-SEARCH responder (RFC 1900 subset used by UPnP).
    async fn serve_ssdp(self: &Arc<Self>, sock: UdpSocket) {
        let mut buf = [0u8; 2048];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            if !self.is_lan_peer(peer.ip()) {
                debug!("UPnP: ignoring SSDP from non-LAN peer {peer}");
                continue;
            }
            let text = String::from_utf8_lossy(&buf[..n]);
            if !text.contains("M-SEARCH") {
                continue;
            }
            let st = text
                .lines()
                .find_map(|l| l.trim().strip_prefix("ST:"))
                .unwrap_or("")
                .trim()
                .to_string();
            let mut advertise = st.is_empty() || st == "ssdp:all";
            if st == DEVICE_TYPE || st == SERVICE_TYPE {
                advertise = true;
            }
            if !advertise {
                continue;
            }
            let location = self.addr.location();
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 CACHE-CONTROL: max-age=1800\r\n\
                 EXT:\r\n\
                 LOCATION: {location}\r\n\
                 SERVER: BalanSir/1.0 UPnP/1.0\r\n\
                 ST: {st}\r\n\
                 USN: uuid:{USN_UUID}::{st}\r\n\
                 \r\n"
            );
            if let Err(e) = sock.send_to(response.as_bytes(), peer).await {
                debug!("UPnP: SSDP reply to {peer} failed: {e}");
            }
        }
    }

    /// HTTP/SOAP control endpoint.
    async fn serve_control(self: &Arc<Self>, listener: TcpListener) {
        loop {
            let Ok((mut stream, peer)) = listener.accept().await else {
                continue;
            };
            if !self.is_lan_peer(peer.ip()) {
                debug!("UPnP: ignoring control request from non-LAN peer {peer}");
                continue;
            }
            let me = Arc::clone(self);
            tokio::spawn(async move { me.handle_connection(&mut stream).await });
        }
    }

    /// Read one HTTP request (headers + optional body) and dispatch.
    async fn handle_connection(self: &Arc<Self>, stream: &mut tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];
        let mut header_end: Option<usize> = None;
        // Read until the header terminator; cap at 16 KiB to avoid abuse.
        while buf.len() < 16 * 1024 {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = find_header_end(&buf) {
                        header_end = Some(pos);
                        break;
                    }
                }
            }
        }
        let Some(header_end) = header_end else {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        };
        let header = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let mut lines = header.lines();
        let Some(request_line) = lines.next() else {
            return;
        };
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("/").to_string();

        // Read the body if Content-Length is present.
        let content_length: usize = lines
            .filter_map(|l| {
                let lower = l.trim().to_ascii_lowercase();
                lower.strip_prefix("content-length:").map(|v| v.to_string())
            })
            .find_map(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let mut body = Vec::with_capacity(content_length);
        body.extend_from_slice(&buf[header_end + 4..]);
        while body.len() < content_length {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
            }
        }
        let body = String::from_utf8_lossy(&body[..content_length.min(body.len())]).to_string();

        let (status, payload) = self.dispatch(&method, &path, &body);
        let _ = write_http_response(stream, status, &payload).await;
    }

    fn dispatch(&self, method: &str, path: &str, body: &str) -> (&'static str, String) {
        match (method, path) {
            ("GET", "/rootDesc.xml") => (STATUS_OK, self.device_description()),
            ("POST", "/upnp/control/WANIPConnection") => self.handle_soap(body),
            _ => (STATUS_NOT_FOUND, String::new()),
        }
    }

    fn device_description(&self) -> String {
        let location = self.addr.location();
        format!(
            "<?xml version=\"1.0\"?>\r\n\
             <root xmlns=\"urn:schemas-upnp-org:device-1-0\">\r\n\
             <specVersion><major>1</major><minor>0</minor></specVersion>\r\n\
             <device>\r\n\
             <deviceType>{DEVICE_TYPE}</deviceType>\r\n\
             <friendlyName>BalanSir Router</friendlyName>\r\n\
             <manufacturer>BalanSir</manufacturer>\r\n\
             <modelName>BalanSir IGD</modelName>\r\n\
             <UDN>uuid:{USN_UUID}</UDN>\r\n\
             <serviceList>\r\n\
             <service>\r\n\
             <serviceType>{SERVICE_TYPE}</serviceType>\r\n\
             <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>\r\n\
             <controlURL>/upnp/control/WANIPConnection</controlURL>\r\n\
             <eventSubURL>/upnp/event/WANIPConnection</eventSubURL>\r\n\
             <SCPDURL>{location}</SCPDURL>\r\n\
             </service>\r\n\
             </serviceList>\r\n\
             </device>\r\n\
             </root>"
        )
    }

    /// Handle a SOAP action. Returns `(status, body)`.
    fn handle_soap(&self, body: &str) -> (&'static str, String) {
        let action = body
            .lines()
            .find_map(|l| {
                let t = l.trim();
                let pos = t.find("<u:")?;
                let rest = &t[pos + 3..];
                rest.split_whitespace()
                    .next()
                    .map(|s| s.trim_end_matches('>').to_string())
            })
            .unwrap_or_default();
        match action.as_str() {
            "AddPortMapping" => self.soap_add_port_mapping(body),
            "DeletePortMapping" => self.soap_delete_port_mapping(body),
            "GetExternalIPAddress" => (STATUS_OK, self.soap_get_external_ip(body)),
            "GetSpecificPortMappingEntry" => self.soap_get_specific(body),
            _ => self.soap_error(401, "Invalid Action"),
        }
    }

    fn soap_add_port_mapping(&self, body: &str) -> (&'static str, String) {
        let external_port = parse_u16(body, "NewExternalPort");
        let internal_port = parse_u16(body, "NewInternalPort");
        let internal_ip = extract_tag(body, "NewInternalClient");
        let proto = extract_tag(body, "NewProtocol").to_ascii_lowercase();
        let lease = parse_u32(body, "NewLeaseDuration").unwrap_or(0);
        let enabled = parse_u32(body, "NewEnabled").unwrap_or(1);

        // Validate.
        if external_port == 0 || internal_port == 0 {
            return self.soap_error(402, "Invalid Args");
        }
        if proto != "tcp" && proto != "udp" {
            return self.soap_error(402, "Invalid Args");
        }
        if enabled == 0 {
            // Not enabled: treat as a delete request.
            return self.soap_delete_port_mapping(body);
        }
        let Ok(ip) = internal_ip.parse::<IpAddr>() else {
            return self.soap_error(402, "Invalid Args");
        };
        if !self.is_private_unicast(ip) {
            warn!("UPnP: refused mapping to non-private target {ip} (WAN abuse) from {body:?}");
            return self.soap_error(606, "Action not authorized");
        }
        if !self.is_lan_peer(ip) {
            warn!("UPnP: refused mapping to target {ip} outside LAN subnet");
            return self.soap_error(606, "Action not authorized");
        }

        // Update the mapping table (renew lease on repeat).
        let expires_at = if lease == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(lease as u64))
        };
        let mapping = PortMapping {
            external_port,
            proto: proto.clone(),
            internal_ip: ip,
            internal_port,
            expires_at,
        };
        self.apply_mapping(&mapping);
        {
            let mut table = self.mappings.lock().unwrap_or_else(|e| e.into_inner());
            table.insert((external_port, proto.clone()), mapping);
        }
        info!(
            "UPnP: added mapping {proto}:{external_port} -> {ip}:{internal_port} (lease {lease}s)"
        );
        (STATUS_OK, soap_response("AddPortMappingResponse"))
    }

    fn soap_delete_port_mapping(&self, body: &str) -> (&'static str, String) {
        let external_port = parse_u16(body, "NewExternalPort");
        let proto = extract_tag(body, "NewProtocol").to_ascii_lowercase();
        self.delete_mapping(external_port, &proto);
        info!("UPnP: deleted mapping {proto}:{external_port}");
        (STATUS_OK, soap_response("DeletePortMappingResponse"))
    }

    fn soap_get_external_ip(&self, body: &str) -> String {
        let _ = body;
        // The WAN IP is the peer the ISP uplink talks to; report the LAN IP of
        // the gateway as the externally reachable address is not meaningful
        // here. We report the LAN address the IGD is bound to.
        let ip = self.addr.ip;
        format!(
            "<?xml version=\"1.0\"?>\r\n\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             xmlns:u=\"{SERVICE_TYPE}\">\r\n\
             <s:Body>\r\n\
             <u:GetExternalIPAddressResponse>\r\n\
             <NewExternalIPAddress>{ip}</NewExternalIPAddress>\r\n\
             </u:GetExternalIPAddressResponse>\r\n\
             </s:Body>\r\n\
             </s:Envelope>"
        )
    }

    fn soap_get_specific(&self, body: &str) -> (&'static str, String) {
        let external_port = parse_u16(body, "NewExternalPort");
        let proto = extract_tag(body, "NewProtocol").to_ascii_lowercase();
        let table = self.mappings.lock().unwrap_or_else(|e| e.into_inner());
        match table.get(&(external_port, proto)) {
            Some(m) => (
                STATUS_OK,
                format!(
                    "<?xml version=\"1.0\"?>\r\n\
                     <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
                     xmlns:u=\"{SERVICE_TYPE}\">\r\n\
                     <s:Body>\r\n\
                     <u:GetSpecificPortMappingEntryResponse>\r\n\
                     <NewRemoteHost></NewRemoteHost>\r\n\
                     <NewExternalPort>{}</NewExternalPort>\r\n\
                     <NewProtocol>{}</NewProtocol>\r\n\
                     <NewInternalPort>{}</NewInternalPort>\r\n\
                     <NewInternalClient>{}</NewInternalClient>\r\n\
                     <NewEnabled>1</NewEnabled>\r\n\
                     <NewPortMappingDescription>BalanSir</NewPortMappingDescription>\r\n\
                     <NewLeaseDuration>0</NewLeaseDuration>\r\n\
                     </u:GetSpecificPortMappingEntryResponse>\r\n\
                     </s:Body>\r\n\
                     </s:Envelope>",
                    m.external_port, m.proto, m.internal_port, m.internal_ip
                ),
            ),
            None => self.soap_error(714, "NoSuchEntryInArray"),
        }
    }

    fn soap_error(&self, code: u16, desc: &str) -> (&'static str, String) {
        let detail = format!(
            "<?xml version=\"1.0\"?>\r\n\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             xmlns:u=\"{SERVICE_TYPE}\">\r\n\
             <s:Body>\r\n\
             <s:Fault>\r\n\
             <faultcode>s:Client</faultcode>\r\n\
             <faultstring>UPnPError</faultstring>\r\n\
             <detail>\r\n\
             <UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\r\n\
             <errorCode>{code}</errorCode>\r\n\
             <errorDescription>{desc}</errorDescription>\r\n\
             </UPnPError>\r\n\
             </detail>\r\n\
             </s:Fault>\r\n\
             </s:Body>\r\n\
             </s:Envelope>"
        );
        (STATUS_OK, detail)
    }

    /// Install (or update) the DNAT rule for a mapping through the executor.
    fn apply_mapping(&self, mapping: &PortMapping) {
        let Some(executor) = self.executor.as_ref() else {
            debug!("UPnP: no executor wired; mapping kept in memory only");
            return;
        };
        let executor = Arc::clone(executor);
        let (external_port, proto, internal_ip, internal_port, wan_if) = (
            mapping.external_port,
            mapping.proto.clone(),
            mapping.internal_ip.to_string(),
            mapping.internal_port,
            self.wan_interface.clone(),
        );
        tokio::spawn(async move {
            match executor
                .upnp_add(external_port, &proto, &internal_ip, internal_port, &wan_if)
                .await
            {
                Ok(result) => debug!(
                    "UPnP: DNAT {proto}:{external_port} applied: {}",
                    result.detail
                ),
                Err(e) => warn!("UPnP: DNAT {proto}:{external_port} apply failed: {e}"),
            }
        });
    }

    fn delete_mapping(&self, external_port: u16, proto: &str) {
        {
            let mut table = self.mappings.lock().unwrap_or_else(|e| e.into_inner());
            table.remove(&(external_port, proto.to_string()));
        }
        let Some(executor) = self.executor.as_ref() else {
            return;
        };
        let executor = Arc::clone(executor);
        let wan_if = self.wan_interface.clone();
        let proto = proto.to_string();
        tokio::spawn(async move {
            match executor.upnp_remove(external_port, &proto, &wan_if).await {
                Ok(_) => debug!("UPnP: DNAT {proto}:{external_port} removed"),
                Err(e) => warn!("UPnP: DNAT {proto}:{external_port} removal failed: {e}"),
            }
        });
    }

    /// Periodic lease cleanup: expired mappings are removed (and their DNAT
    /// rule deleted). Runs until shutdown.
    async fn expiry_loop(self: &Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            let now = Instant::now();
            let expired: Vec<(u16, String)> = {
                let table = self.mappings.lock().unwrap_or_else(|e| e.into_inner());
                table
                    .iter()
                    .filter_map(|(k, m)| {
                        m.expires_at
                            .map(|exp| (k.clone(), exp <= now))
                            .filter(|(_, expired)| *expired)
                            .map(|(k, _)| k)
                    })
                    .collect()
            };
            for (port, proto) in expired {
                warn!("UPnP: mapping {proto}:{port} lease expired; removing");
                self.delete_mapping(port, &proto);
            }
        }
    }

    fn is_lan_peer(&self, ip: IpAddr) -> bool {
        match (ip, parse_cidr(&self.lan_subnet)) {
            (IpAddr::V4(v4), Some((net, prefix))) => {
                let addr_bits = u32::from_be_bytes(v4.octets());
                let net_bits = u32::from_be_bytes(net.octets());
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (addr_bits & mask) == (net_bits & mask)
            }
            _ => false,
        }
    }

    fn is_private_unicast(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // RFC 1918 private ranges (10/8, 172.16/12, 192.168/16).
                let rfc1918 = octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168);
                rfc1918 && !v4.is_loopback() && !v4.is_multicast() && !v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                // ULA (fc00::/7) or link-local (fe80::/10) or loopback-adjacent.
                (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80
            }
        }
    }
}

const STATUS_OK: &str = "200 OK";
const STATUS_NOT_FOUND: &str = "404 Not Found";

fn soap_response(action: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\r\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         xmlns:u=\"{SERVICE_TYPE}\">\r\n\
         <s:Body>\r\n\
         <u:{action}></u:{action}>\r\n\
         </s:Body>\r\n\
         </s:Envelope>"
    )
}

/// Extract the content of a single `<Tag>...</Tag>` (case-insensitive name
/// match, namespace-agnostic). Returns empty string when absent.
fn extract_tag(body: &str, tag: &str) -> String {
    let lower = body.to_ascii_lowercase();
    let tag_lower = tag.to_ascii_lowercase();
    let start_marker = format!("<{tag_lower}>");
    let Some(open) = lower.find(&start_marker) else {
        return String::new();
    };
    let content_start = open + start_marker.len();
    let Some(close) = lower[content_start..].find("</") else {
        return String::new();
    };
    body[content_start..content_start + close]
        .trim()
        .to_string()
}

fn parse_u16(body: &str, tag: &str) -> u16 {
    extract_tag(body, tag).parse().unwrap_or(0)
}

fn parse_u32(body: &str, tag: &str) -> Option<u32> {
    extract_tag(body, tag).parse().ok()
}

/// Find the `\r\n\r\n` (or `\n\n`) header terminator.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n"))
}

async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    payload: &str,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {payload}",
        payload.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

fn parse_cidr(cidr: &str) -> Option<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = cidr.trim().split_once('/')?;
    let ip = ip.parse::<std::net::Ipv4Addr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    Some((ip, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> UpnpManager {
        UpnpManager::new(
            None,
            "192.168.3.2".parse().unwrap(),
            "192.168.3.0/24",
            "eth0",
            3721,
        )
    }

    #[test]
    fn lan_peer_detection() {
        let m = manager();
        assert!(m.is_lan_peer("192.168.3.10".parse().unwrap()));
        assert!(m.is_lan_peer("192.168.3.1".parse().unwrap()));
        assert!(!m.is_lan_peer("192.168.4.10".parse().unwrap()));
        assert!(!m.is_lan_peer("10.0.0.1".parse().unwrap()));
        assert!(!m.is_lan_peer("::1".parse().unwrap()));
    }

    #[test]
    fn tag_extraction() {
        let body = r#"<s:Envelope><s:Body><u:AddPortMapping>
            <NewExternalPort>8080</NewExternalPort>
            <NewProtocol>TCP</NewProtocol>
            <NewInternalClient>192.168.3.10</NewInternalClient>
            <NewInternalPort>80</NewInternalPort>
            <NewLeaseDuration>3600</NewLeaseDuration>
            <NewEnabled>1</NewEnabled>
        </u:AddPortMapping></s:Body></s:Envelope>"#;
        assert_eq!(extract_tag(body, "NewExternalPort"), "8080");
        assert_eq!(extract_tag(body, "NewProtocol"), "TCP");
        assert_eq!(extract_tag(body, "NewInternalClient"), "192.168.3.10");
        assert_eq!(extract_tag(body, "NewInternalPort"), "80");
        assert_eq!(extract_tag(body, "NewLeaseDuration"), "3600");
        assert_eq!(parse_u16(body, "NewExternalPort"), 8080);
        assert_eq!(parse_u32(body, "NewLeaseDuration"), Some(3600));
        assert_eq!(extract_tag(body, "NewRemoteHost"), "");
    }

    #[test]
    fn private_unicast_rejects_abuse_targets() {
        let m = manager();
        assert!(m.is_private_unicast("192.168.3.10".parse().unwrap()));
        assert!(!m.is_private_unicast("8.8.8.8".parse().unwrap()));
        assert!(!m.is_private_unicast("127.0.0.1".parse().unwrap()));
        assert!(!m.is_private_unicast("224.0.0.1".parse().unwrap()));
    }

    #[test]
    fn add_port_mapping_validation() {
        let m = manager();
        // Port 0 rejected.
        let body = r#"<s:Body><u:AddPortMapping>
            <NewExternalPort>0</NewExternalPort><NewInternalPort>80</NewInternalPort>
            <NewInternalClient>192.168.3.10</NewInternalClient><NewProtocol>TCP</NewProtocol>
            <NewLeaseDuration>0</NewLeaseDuration><NewEnabled>1</NewEnabled>
        </u:AddPortMapping></s:Body>"#;
        let (status, resp) = m.handle_soap(body);
        assert_eq!(status, STATUS_OK);
        assert!(resp.contains("402"));

        // Non-private target rejected.
        let body = r#"<s:Body><u:AddPortMapping>
            <NewExternalPort>8080</NewExternalPort><NewInternalPort>80</NewInternalPort>
            <NewInternalClient>8.8.8.8</NewInternalClient><NewProtocol>TCP</NewProtocol>
            <NewLeaseDuration>0</NewLeaseDuration><NewEnabled>1</NewEnabled>
        </u:AddPortMapping></s:Body>"#;
        let (status, resp) = m.handle_soap(body);
        assert_eq!(status, STATUS_OK);
        assert!(resp.contains("606"));

        // Target outside LAN subnet rejected.
        let body = r#"<s:Body><u:AddPortMapping>
            <NewExternalPort>8080</NewExternalPort><NewInternalPort>80</NewInternalPort>
            <NewInternalClient>10.0.0.5</NewInternalClient><NewProtocol>TCP</NewProtocol>
            <NewLeaseDuration>0</NewLeaseDuration><NewEnabled>1</NewEnabled>
        </u:AddPortMapping></s:Body>"#;
        let (status, resp) = m.handle_soap(body);
        assert_eq!(status, STATUS_OK);
        assert!(resp.contains("606"));
    }

    #[test]
    fn valid_mapping_is_installed_in_memory() {
        let m = manager();
        let body = r#"<s:Body><u:AddPortMapping>
            <NewExternalPort>8080</NewExternalPort><NewInternalPort>80</NewInternalPort>
            <NewInternalClient>192.168.3.10</NewInternalClient><NewProtocol>TCP</NewProtocol>
            <NewLeaseDuration>0</NewLeaseDuration><NewEnabled>1</NewEnabled>
        </u:AddPortMapping></s:Body>"#;
        let (status, resp) = m.handle_soap(body);
        assert_eq!(status, STATUS_OK);
        assert!(resp.contains("AddPortMappingResponse"));
        let table = m.mappings.lock().unwrap();
        let m2 = table.get(&(8080, "tcp".to_string())).unwrap();
        assert_eq!(m2.internal_port, 80);
        assert_eq!(m2.internal_ip.to_string(), "192.168.3.10");
        assert_eq!(m2.expires_at, None);
    }

    #[test]
    fn delete_mapping_removes() {
        let m = manager();
        let body = r#"<s:Body><u:AddPortMapping>
            <NewExternalPort>8080</NewExternalPort><NewInternalPort>80</NewInternalPort>
            <NewInternalClient>192.168.3.10</NewInternalClient><NewProtocol>UDP</NewProtocol>
            <NewLeaseDuration>0</NewLeaseDuration><NewEnabled>1</NewEnabled>
        </u:AddPortMapping></s:Body>"#;
        let _ = m.handle_soap(body);
        let del = r#"<s:Body><u:DeletePortMapping>
            <NewExternalPort>8080</NewExternalPort><NewProtocol>UDP</NewProtocol>
        </u:DeletePortMapping></s:Body>"#;
        let (status, _) = m.handle_soap(del);
        assert_eq!(status, STATUS_OK);
        assert!(m.mappings.lock().unwrap().is_empty());
    }
}
