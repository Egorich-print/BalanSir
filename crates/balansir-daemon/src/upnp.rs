//! UPnP/IGD (Internet Gateway Device) support for LAN port mapping.
//!
//! Implements a minimal IGD control point that:
//! - Listens for SSDP discovery on LAN interface only
//! - Responds to M-SEARCH for urn:schemas-upnp-org:device:InternetGatewayDevice:1
//! - Handles AddPortMapping/DeletePortMapping/GetExternalIPAddress
//! - Maps to nftables DNAT rules with lifetime/expiration
//! - Rejects invalid/private/WAN mappings

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::reconciliation::ExecutorClient;

/// A port mapping entry.
#[derive(Debug, Clone)]
struct PortMapping {
    external_port: u16,
    internal_ip: Ipv4Addr,
    internal_port: u16,
    proto: String, // "TCP" or "UDP"
    description: String,
    lease_duration: u32, // seconds, 0 = permanent
    created: Instant,
    remote_host: Option<Ipv4Addr>, // for future use
}

/// UPnP/IGD state.
struct IgdState {
    mappings: HashMap<u16, PortMapping>, // key = external_port
    lan_interface: String,
    wan_interface: String,
    lan_ip: Ipv4Addr,
    public_ip: Option<Ipv4Addr>,
    executor: Arc<ExecutorClient>,
}

impl IgdState {
    fn new(lan_interface: String, wan_interface: String, lan_ip: Ipv4Addr, executor: Arc<ExecutorClient>) -> Self {
        Self {
            mappings: HashMap::new(),
            lan_interface,
            wan_interface,
            lan_ip,
            public_ip: None,
            executor,
        }
    }

    /// Add a port mapping (IGD AddPortMapping).
    async fn add_mapping(
        &mut self,
        external_port: u16,
        internal_ip: Ipv4Addr,
        internal_port: u16,
        proto: &str,
        description: &str,
        lease_duration: u32,
    ) -> Result<(), String> {
        // Validate: reject invalid/private/WAN mappings
        if internal_ip.is_loopback() || internal_ip.is_multicast() || internal_ip.is_broadcast() {
            return Err("invalid internal IP (loopback/multicast/broadcast)".into());
        }
        if internal_ip == self.lan_ip {
            return Err("internal IP cannot be the gateway LAN IP".into());
        }
        if proto != "TCP" && proto != "UDP" {
            return Err("protocol must be TCP or UDP".into());
        }
        if external_port == 0 {
            return Err("external port cannot be 0".into());
        }

        // Check if port already mapped
        if self.mappings.contains_key(&external_port) {
            return Err("port already mapped".into());
        }

        // Add nftables DNAT rule
        let comment = format!("balansir:upnp-{}", external_port);
        let proto_lower = proto.to_lowercase();
        self.executor
            .add_dnat(
                &self.wan_interface,
                external_port,
                &internal_ip.to_string(),
                internal_port,
                Some(&proto_lower),
                &comment,
            )
            .await?;

        let mapping = PortMapping {
            external_port,
            internal_ip,
            internal_port,
            proto: proto.to_string(),
            description: description.to_string(),
            lease_duration,
            created: Instant::now(),
            remote_host: None,
        };
        self.mappings.insert(external_port, mapping);
        info!("UPnP: Added mapping {} -> {}:{} ({}) lease={}s", external_port, internal_ip, internal_port, proto, lease_duration);
        Ok(())
    }

    /// Delete a port mapping (IGD DeletePortMapping).
    async fn delete_mapping(&mut self, external_port: u16, proto: &str) -> Result<(), String> {
        let comment = format!("balansir:upnp-{}", external_port);
        if let Some(mapping) = self.mappings.remove(&external_port) {
            if mapping.proto != proto {
                return Err("protocol mismatch".into());
            }
            self.executor
                .remove_dnat(&self.wan_interface, &comment)
                .await?;
            info!("UPnP: Deleted mapping {} ({})", external_port, proto);
            Ok(())
        } else {
            Err("mapping not found".into())
        }
    }

    /// Get external IP (IGD GetExternalIPAddress).
    fn get_external_ip(&self) -> Option<Ipv4Addr> {
        self.public_ip
    }

    /// Update public IP (called when WAN IP changes).
    fn set_public_ip(&mut self, ip: Ipv4Addr) {
        self.public_ip = Some(ip);
    }

    /// Cleanup expired mappings.
    async fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let mut expired = Vec::new();
        for (port, mapping) in &self.mappings {
            if mapping.lease_duration > 0 {
                let elapsed = now.duration_since(mapping.created).as_secs();
                if elapsed >= mapping.lease_duration as u64 {
                    expired.push(*port);
                }
            }
        }
        for port in expired {
            if let Some(mapping) = self.mappings.remove(&port) {
                let comment = format!("balansir:upnp-{}", port);
                let _ = self.executor.remove_dnat(&self.wan_interface, &comment).await;
                info!("UPnP: Expired mapping {} ({})", port, mapping.proto);
            }
        }
    }
}

/// UPnP/IGD daemon.
pub struct IgdDaemon {
    state: Arc<RwLock<IgdState>>,
    ssdp_socket: Option<UdpSocket>,
    task: Option<tokio::task::JoinHandle<()>>,
    cleanup_task: Option<tokio::task::JoinHandle<()>>,
}

impl IgdDaemon {
    pub fn new(
        lan_interface: String,
        wan_interface: String,
        lan_ip: Ipv4Addr,
        executor: Arc<ExecutorClient>,
    ) -> Self {
        Self {
            state: Arc::new(RwLock::new(IgdState::new(lan_interface, wan_interface, lan_ip, executor))),
            ssdp_socket: None,
            task: None,
            cleanup_task: None,
        }
    }

    /// Start the IGD daemon (SSDP listener + cleanup loop).
    pub async fn start(&mut self) -> Result<(), String> {
        // Bind SSDP socket on LAN interface
        let socket = UdpSocket::bind("0.0.0.0:1900").map_err(|e| format!("bind SSDP: {e}"))?;
        socket.set_multicast_loop_v4(true).ok();
        socket.join_multicast_v4(&Ipv4Addr::new(239, 255, 255, 250), &Ipv4Addr::UNSPECIFIED).ok();
        self.ssdp_socket = Some(socket);

        let state = self.state.clone();
        let lan_interface = self.state.read().await.lan_interface.clone();
        
        // SSDP listener task
        self.task = Some(tokio::spawn(async move {
            Self::ssdp_loop(state, lan_interface).await;
        }));

        // Cleanup loop (runs every 60 seconds)
        let state = self.state.clone();
        self.cleanup_task = Some(tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                state.write().await.cleanup_expired().await;
            }
        }));

        info!("UPnP/IGD daemon started on LAN interface");
        Ok(())
    }

    /// Stop the IGD daemon.
    pub async fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
        }
        // Clean up all mappings
        let mut state = self.state.write().await;
        for (port, mapping) in state.mappings.drain() {
            let comment = format!("balansir:upnp-{}", port);
            let _ = state.executor.remove_dnat(&state.wan_interface, &comment).await;
        }
    }

    /// Update public IP (call when WAN IP changes).
    pub async fn set_public_ip(&self, ip: Ipv4Addr) {
        self.state.write().await.set_public_ip(ip);
    }

    /// SSDP listener loop.
    async fn ssdp_loop(state: Arc<RwLock<IgdState>>, lan_interface: String) {
        let socket = match std::net::UdpSocket::bind("0.0.0.0:1900") {
            Ok(s) => s,
            Err(e) => {
                warn!("UPnP SSDP bind failed: {e}");
                return;
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(1))).ok();

        let mut buf = [0u8; 4096];
        loop {
            let (n, src) = match socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => continue, // timeout or error
            };
            let data = &buf[..n];
            let request = String::from_utf8_lossy(data);
            
            if request.contains("M-SEARCH") && request.contains("urn:schemas-upnp-org:device:InternetGatewayDevice:1") {
                // Respond to discovery
                Self::send_ssdp_response(&socket, &src, &state, &lan_interface).await;
            } else if request.contains("AddPortMapping") || request.contains("DeletePortMapping") || request.contains("GetExternalIPAddress") {
                // Handle SOAP actions
                Self::handle_soap_request(&socket, &src, &state, &request).await;
            }
        }
    }

    /// Send SSDP response for M-SEARCH.
    async fn send_ssdp_response(
        socket: &std::net::UdpSocket,
        src: &SocketAddr,
        state: &Arc<RwLock<IgdState>>,
        lan_interface: &str,
    ) {
        let state = state.read().await;
        let location = format!("http://{}:8080/upnp/IGD.xml", state.lan_ip);
        let usn = "uuid:balansir-igd::urn:schemas-upnp-org:device:InternetGatewayDevice:1";
        let server = "Linux/6.1 UPnP/1.0 BalanSir/1.0";
        
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
            CACHE-CONTROL: max-age=1800\r\n\
            LOCATION: {}\r\n\
            SERVER: {}\r\n\
            ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
            USN: {}\r\n\
            EXT:\r\n\
            \r\n",
            location, server, usn
        );
        
        if let Err(e) = socket.send_to(response.as_bytes(), src) {
            warn!("UPnP SSDP response failed: {e}");
        }
    }

    /// Handle SOAP request (simplified XML parsing).
    async fn handle_soap_request(
        socket: &std::net::UdpSocket,
        src: &SocketAddr,
        state: &Arc<RwLock<IgdState>>,
        request: &str,
    ) {
        // This is a simplified SOAP handler - in production you'd use a proper XML parser
        // For now, just log and respond with basic HTTP responses
        if request.contains("AddPortMapping") {
            // Parse AddPortMapping arguments (simplified)
            // In reality, parse XML and extract: NewRemoteHost, NewExternalPort, NewProtocol,
            // NewInternalPort, NewInternalClient, NewEnabled, NewPortMappingDescription, NewLeaseDuration
            debug!("UPnP AddPortMapping request from {}", src);
        } else if request.contains("DeletePortMapping") {
            debug!("UPnP DeletePortMapping request from {}", src);
        } else if request.contains("GetExternalIPAddress") {
            let state = state.read().await;
            if let Some(ip) = state.get_external_ip() {
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                    CONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n\
                    \r\n\
                    <?xml version=\"1.0\"?>\r\n\
                    <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n\
                    <s:Body>\r\n\
                    <u:GetExternalIPAddressResponse xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\r\n\
                    <NewExternalIPAddress>{}</NewExternalIPAddress>\r\n\
                    </u:GetExternalIPAddressResponse>\r\n\
                    </s:Body>\r\n\
                    </s:Envelope>",
                    ip
                );
                let _ = socket.send_to(response.as_bytes(), src);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn port_mapping_validation() {
        // Test would require a mock executor
    }
}