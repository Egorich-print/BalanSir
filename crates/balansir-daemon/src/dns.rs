use async_trait::async_trait;
use balansir_common::{Capabilities, DriverError, DriverId, HealthStatus};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinHandle;

use crate::driver::ComponentDriver;
use crate::reconciliation::DnsRegistry;

fn ss_bin() -> std::path::PathBuf {
    balansir_common::paths::resolve_bin_or_default("ss")
}

/// Per-upstream forward timeout. A failed or slow upstream is skipped in
/// favor of the next one, so a single dead server cannot stall the network.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
/// Fixed TTL applied to cached responses (we relay opaque DNS messages and do
/// not re-write TTLs; 30s is a safe floor for typical A/AAAA records).
const CACHE_TTL: Duration = Duration::from_secs(30);

/// SOCKS5 UDP Associate relay for routing DNS queries through a SOCKS5 proxy.
///
/// Implements the SOCKS5 UDP ASSOCIATE protocol (RFC 1928) to route UDP packets
/// through a SOCKS5 proxy with UDP support (e.g., Xray SOCKS5 inbound).
struct Socks5UdpRelay {
    /// The UDP socket connected to the SOCKS5 relay address, used to send/receive
    /// SOCKS5-wrapped UDP packets.
    udp_socket: UdpSocket,
}

impl Socks5UdpRelay {
    /// Establish a SOCKS5 UDP ASSOCIATE connection to the given proxy address.
    ///
    /// Performs SOCKS5 handshake (no auth) and UDP ASSOCIATE command,
    /// returning a relay that can send/receive UDP packets through the proxy.
    async fn connect(proxy_addr: SocketAddr) -> io::Result<Self> {
        // Connect to SOCKS5 proxy via TCP
        let mut tcp = TcpStream::connect(proxy_addr).await?;

        // SOCKS5 handshake: VER=5, NMETHODS=1, METHODS=[0x00 (no auth)]
        tcp.write_all(&[0x05, 0x01, 0x00]).await?;
        tcp.flush().await?;

        // Read server response: VER=5, METHOD=0x00
        let mut resp = [0u8; 2];
        tcp.read_exact(&mut resp).await?;
        if resp[0] != 0x05 || resp[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS5 handshake failed",
            ));
        }

        // Send UDP ASSOCIATE command:
        // VER=5, CMD=3 (UDP ASSOCIATE), RSV=0, ATYP=1 (IPv4), DST.ADDR=0.0.0.0, DST.PORT=0
        let cmd = [0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        tcp.write_all(&cmd).await?;
        tcp.flush().await?;

        // Read server response: VER=5, REP=0, RSV=0, ATYP, BND.ADDR, BND.PORT
        let mut resp = [0u8; 10];
        tcp.read_exact(&mut resp).await?;
        if resp[0] != 0x05 || resp[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP ASSOCIATE failed",
            ));
        }

        // Parse bound address (BND.ADDR, BND.PORT) from response
        let relay_addr = parse_socks5_addr(&resp[3..])?;

        // Create local UDP socket for relay communication
        let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        udp_socket.connect(relay_addr).await?;

        Ok(Self { udp_socket })
    }

    /// Send a DNS query to the upstream through the SOCKS5 relay.
    ///
    /// Wraps the payload in a SOCKS5 UDP header (RSV=0, FRAG=0, ATYP, DST.ADDR, DST.PORT).
    async fn send(&self, query: &[u8], upstream: SocketAddr) -> io::Result<()> {
        let mut packet = Vec::with_capacity(10 + query.len());
        // SOCKS5 UDP header: RSV=0 (2 bytes), FRAG=0 (1 byte)
        packet.extend_from_slice(&[0x00, 0x00, 0x00]);
        // ATYP and DST.ADDR, DST.PORT
        match upstream {
            SocketAddr::V4(v4) => {
                packet.push(0x01); // ATYP=1 (IPv4)
                packet.extend_from_slice(&v4.ip().octets());
                packet.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                packet.push(0x04); // ATYP=4 (IPv6)
                packet.extend_from_slice(&v6.ip().octets());
                packet.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        packet.extend_from_slice(query);
        self.udp_socket.send(&packet).await.map(|_| ())
    }

    /// Receive a response from the SOCKS5 relay.
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.udp_socket.recv(buf).await?;
        // Strip SOCKS5 UDP header (RSV=2, FRAG=1, ATYP=1, DST.ADDR, DST.PORT)
        // SOCKS5 UDP header format (RFC 1928):
        // RSV (2 bytes) = 0x0000
        // FRAG (1 byte) = 0x00
        // ATYP (1 byte) = address type
        // DST.ADDR (variable) = destination address
        // DST.PORT (2 bytes) = destination port
        // DATA = payload
        if n < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Short SOCKS5 packet",
            ));
        }
        // Check RSV=0, FRAG=0
        if buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SOCKS5 UDP header (RSV/FRAG)",
            ));
        }
        let atyp = buf[3];
        let header_len = match atyp {
            0x01 => 2 + 1 + 1 + 4 + 2, // RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) = 10
            0x03 => {
                let addr_len = buf[4] as usize;
                2 + 1 + 1 + 1 + addr_len + 2 // RSV(2) + FRAG(1) + ATYP(1) + LEN(1) + ADDR + PORT(2)
            }
            0x04 => 2 + 1 + 1 + 16 + 2, // IPv6
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Unknown ATYP")),
        };
        if n < header_len || buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SOCKS5 UDP header",
            ));
        }
        // Copy payload to beginning of buffer using split_at_mut
        let (prefix, suffix) = buf.split_at_mut(header_len);
        prefix[..n - header_len].copy_from_slice(&suffix[..n - header_len]);
        Ok(n - header_len)
    }
}

/// Parse a SOCKS5 address from bytes (ATYP + ADDR + PORT).
fn parse_socks5_addr(bytes: &[u8]) -> io::Result<SocketAddr> {
    if bytes.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty address"));
    }
    match bytes[0] {
        0x01 => {
            // IPv4: 4 bytes + 2 port
            if bytes.len() < 6 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Short IPv4"));
            }
            let ip = std::net::Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]);
            let port = u16::from_be_bytes([bytes[5], bytes[6]]);
            Ok(SocketAddr::from((ip, port)))
        }
        0x04 => {
            // IPv6: 16 bytes + 2 port
            if bytes.len() < 18 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Short IPv6"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([bytes[18], bytes[19]]);
            Ok(SocketAddr::from((ip, port)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unsupported ATYP",
        )),
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsForwarderConfig {
    /// Listen address
    pub listen: SocketAddr,
    /// Upstream DNS servers
    pub upstreams: Vec<SocketAddr>,
    /// Enable DNS-over-HTTPS
    pub doh: bool,
    /// Enable DNS-over-TLS
    pub dot: bool,
    /// Cache size (number of entries)
    pub cache_size: usize,
    /// Enable DNS logging
    pub log_queries: bool,
    /// Blocklist: domains (and their subdomains) answered with NXDOMAIN.
    #[serde(default)]
    pub blocklist: Vec<String>,
    /// Allowlist: domains (and their subdomains) that override the blocklist.
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// Optional SOCKS5 proxy for upstream queries (e.g., VPN SOCKS5 inbound).
    /// When set, upstream DNS queries are sent through this proxy via SOCKS5 UDP.
    #[serde(default)]
    pub socks5_proxy: Option<SocketAddr>,
}

impl Default for DnsForwarderConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:53".parse().unwrap(),
            upstreams: vec!["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()],
            doh: false,
            dot: false,
            cache_size: 10000,
            log_queries: false,
            blocklist: Vec::new(),
            allowlist: Vec::new(),
            socks5_proxy: None,
        }
    }
}

impl DnsForwarderConfig {
    /// Load a DNS forwarder config from a TOML file (`BALANSIR_DNS_CONFIG`).
    pub fn from_file(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        toml::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))
    }
}

/// Small bounded query-response cache. Keyed by the raw query bytes (no
/// parsing, no injection surface); entries expire after `CACHE_TTL`.
type CacheEntry = (Vec<u8>, Instant);

#[derive(Default)]
struct DnsCache(Mutex<HashMap<Vec<u8>, CacheEntry>>);

impl DnsCache {
    fn get(&self, query: &[u8]) -> Option<Vec<u8>> {
        let mut cache = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((resp, exp)) = cache.get(query) {
            if *exp > Instant::now() {
                return Some(resp.clone());
            }
            cache.remove(query);
        }
        None
    }

    fn put(&self, query: Vec<u8>, response: Vec<u8>, cap: usize) {
        if cap == 0 {
            return;
        }
        let mut cache = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= cap {
            cache.retain(|_, (_, exp)| *exp > Instant::now());
            if cache.len() >= cap {
                cache.clear();
            }
        }
        cache.insert(query, (response, Instant::now() + CACHE_TTL));
    }
}

/// Send one DNS query to `upstream` and return the (opaque) response.
///
/// If `socks5_relay` is provided, the query is sent through the SOCKS5 UDP
/// associate relay; otherwise, a direct UDP connection is used.
async fn forward_query(
    query: &[u8],
    upstream: SocketAddr,
    socks5_relay: Option<&Socks5UdpRelay>,
) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let result = match socks5_relay {
        Some(relay) => {
            relay.send(query, upstream).await.ok()?;
            relay.recv(&mut buf).await.ok()
        }
        None => {
            let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
            sock.connect(upstream).await.ok()?;
            sock.send(query).await.ok()?;
            tokio::time::timeout(FORWARD_TIMEOUT, sock.recv(&mut buf))
                .await
                .ok()?
                .ok()
        }
    };
    result.map(|n| buf[..n].to_vec())
}

/// DNS filtering decision for a queried domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainDecision {
    /// Resolve through the upstreams as usual.
    Pass,
    /// Answer locally with NXDOMAIN; never send the query upstream.
    Block,
}

/// Classify a query domain against the blocklist/allowlist.
///
/// A list entry matches the domain itself and every subdomain (suffix match),
/// so a single `example.com` entry covers `a.example.com` and `x.y.example.com`.
/// The allowlist wins over the blocklist at every depth: `ads.example.com` in
/// the allowlist unblocks that exact domain even when `example.com` is blocked.
fn classify_domain(
    domain: &str,
    block: &HashSet<String>,
    allow: &HashSet<String>,
) -> DomainDecision {
    let lower = domain.trim_end_matches('.').to_ascii_lowercase();
    let mut labels: Vec<&str> = lower.split('.').collect();
    // Check the fully-qualified name first (most specific), then each parent.
    while !labels.is_empty() {
        let candidate = labels.join(".");
        if allow.contains(&candidate) {
            return DomainDecision::Pass;
        }
        if block.contains(&candidate) {
            return DomainDecision::Block;
        }
        labels.remove(0);
    }
    DomainDecision::Pass
}

/// Build a minimal NXDOMAIN response mirroring the query's header (echo the
/// query id, set QR + NXDOMAIN, zero answers) so DNS clients see a normal,
/// cacheable negative answer with no upstream round-trip.
fn nxdomain_response(query: &[u8]) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() >= 2 {
        resp[0] = query[0];
        resp[1] = query[1];
    }
    if resp.len() >= 4 {
        // QR=1, opcode preserved, RD preserved; RCODE=3 (NXDOMAIN).
        resp[2] = (query[2] & 0x78) | 0x80;
        resp[3] = (query[3] & 0x07) | 0x03;
    }
    // ANCOUNT = NSCOUNT = ARCOUNT = 0.
    for i in 6..12 {
        if resp.len() > i {
            resp[i] = 0;
        }
    }
    resp
}

/// DNS filtering sets shared by the forward loop (blocklist/allowlist).
#[derive(Clone)]
struct DnsFilterSets {
    block: std::sync::Arc<HashSet<String>>,
    allow: std::sync::Arc<HashSet<String>>,
}

impl DnsFilterSets {
    fn classify(&self, domain: &str) -> DomainDecision {
        classify_domain(domain, &self.block, &self.allow)
    }
}

/// UDP DNS forwarding loop. Answers queries from `socket`, failing over
/// across `upstreams` in round-robin order, and caches responses.
///
/// When a `DnsRegistry` is attached (the shared DNS observation truth for the
/// policy plane), every response forwarded from an upstream is parsed and its
/// A/AAAA answer set is recorded — so real DNS traffic feeds the flow
/// compiler and the B4 observer. Cached responses are not re-parsed (the
/// cache TTL bounds registry freshness). Blocked domains are answered with
/// NXDOMAIN without an upstream round-trip and never reach the registry.
///
/// If `vpn_proxy` is set, upstream DNS queries are sent through the SOCKS5
/// proxy via UDP associate, routing DNS through the VPN tunnel.
#[allow(clippy::too_many_arguments)]
async fn forward_loop(
    socket: UdpSocket,
    upstreams: Vec<SocketAddr>,
    cache: DnsCache,
    cache_size: usize,
    log_queries: bool,
    registry: Option<Arc<DnsRegistry>>,
    filter: DnsFilterSets,
    vpn_proxy: Arc<Mutex<Option<SocketAddr>>>,
) {
    let mut round_robin = 0usize;
    let mut buf = vec![0u8; 4096];

    // SOCKS5 relay state - created lazily when VPN proxy is set
    let mut socks5_relay: Option<Socks5UdpRelay> = None;
    let mut last_proxy_addr: Option<SocketAddr> = None;

    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => return, // listener closed
        };
        let query = buf[..n].to_vec();
        if query.is_empty() {
            continue;
        }
        if log_queries {
            tracing::debug!(from = %peer, bytes = n, "dns query");
        }

        // Check if VPN proxy has changed and recreate relay if needed
        let current_proxy = *vpn_proxy.lock().unwrap_or_else(|e| e.into_inner());
        if current_proxy != last_proxy_addr {
            let mut relay: Option<Socks5UdpRelay> = None;
            if let Some(addr) = current_proxy {
                match tokio::time::timeout(Duration::from_secs(3), Socks5UdpRelay::connect(addr))
                    .await
                {
                    Ok(Ok(rel)) => {
                        tracing::info!(%addr, "SOCKS5 UDP relay established for DNS");
                        relay = Some(rel);
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(%addr, error=%e, "Failed to establish SOCKS5 UDP relay, using direct");
                    }
                    Err(_) => {
                        tracing::warn!(%addr, "SOCKS5 UDP relay connection timeout, using direct");
                    }
                }
            }
            socks5_relay = relay;
            last_proxy_addr = current_proxy;
        }

        let socks5_relay_ref = socks5_relay.as_ref();

        // DNS filtering: blocklist/allowlist decide locally, before any
        // upstream contact (a blocked query never leaks to a resolver).
        let decision = crate::dns_plane::query_name(&query)
            .map(|domain| filter.classify(&domain))
            .unwrap_or(DomainDecision::Pass);
        if log_queries {
            tracing::debug!(domain = ?crate::dns_plane::query_name(&query), decision = ?decision, "dns filter");
        }
        if decision == DomainDecision::Block {
            let response = nxdomain_response(&query);
            let _ = socket.send_to(&response, peer).await;
            continue;
        }

        let response = match cache.get(&query) {
            Some(r) => Some(r),
            None => {
                let mut response = None;
                for offset in 0..upstreams.len() {
                    let idx = (round_robin + offset) % upstreams.len();
                    if let Some(r) = forward_query(&query, upstreams[idx], socks5_relay_ref).await {
                        response = Some(r);
                        break;
                    }
                }
                round_robin = (round_robin + 1).max(1) % upstreams.len();
                if let Some(r) = &response {
                    cache.put(query.clone(), r.clone(), cache_size);
                    // P6 (ADR-023): record the DNS observation for the policy
                    // plane (flow compiler + B4 observer).
                    if let Some(registry) = &registry {
                        if crate::dns_plane::ingest(registry, &query, r) {
                            tracing::trace!("dns observation recorded");
                        }
                    }
                }
                response
            }
        };

        if let Some(r) = response {
            let _ = socket.send_to(&r, peer).await;
        }
    }
}

/// DNS forwarder driver: a real UDP DNS proxy with upstream failover and a
/// bounded cache. All system logic is Rust (no external daemon).
pub struct DnsForwarderDriver {
    id: DriverId,
    config: DnsForwarderConfig,
    running: bool,
    health: HealthStatus,
    task: Option<JoinHandle<()>>,
    local: Option<SocketAddr>,
    /// Shared DNS observation truth for the policy plane (P6/ADR-023).
    /// When attached, forwarded responses populate it (domain → A/AAAA).
    registry: Option<Arc<DnsRegistry>>,
    /// Shared VPN SOCKS5 proxy address. When set, upstream DNS queries are
    /// sent through this proxy via SOCKS5 UDP associate.
    vpn_proxy: Arc<Mutex<Option<SocketAddr>>>,
}

impl DnsForwarderDriver {
    /// Create a new DNS forwarder driver
    pub fn new(id: DriverId, config: DnsForwarderConfig) -> Self {
        Self {
            id,
            config,
            running: false,
            health: HealthStatus::Unknown,
            task: None,
            local: None,
            registry: None,
            vpn_proxy: Arc::new(Mutex::new(None)),
        }
    }

    /// Attach the shared `DnsRegistry` so forwarded responses become policy
    /// plane observations. Must be called before `start`.
    pub fn attach_registry(&mut self, registry: Arc<DnsRegistry>) {
        self.registry = Some(registry);
    }

    /// Set the VPN SOCKS5 proxy address for upstream queries.
    /// When set, upstream DNS queries are sent through this proxy via SOCKS5 UDP associate.
    /// Pass `None` to disable VPN proxy and use direct upstream connections.
    pub fn set_vpn_proxy(&self, addr: Option<SocketAddr>) {
        *self.vpn_proxy.lock().unwrap_or_else(|e| e.into_inner()) = addr;
    }

    /// Actual bound listener address (useful when configured with port 0).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local
    }
}

#[async_trait]
impl ComponentDriver for DnsForwarderDriver {
    fn id(&self) -> DriverId {
        self.id
    }

    fn name(&self) -> &str {
        "DNS Forwarder"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::DNS
    }

    async fn start(&mut self) -> Result<(), DriverError> {
        if self.running {
            return Ok(());
        }
        let upstreams = if self.config.upstreams.is_empty() {
            vec!["1.1.1.1:53".parse().unwrap()]
        } else {
            self.config.upstreams.clone()
        };

        let socket = UdpSocket::bind(self.config.listen).await.map_err(|e| {
            DriverError::StartFailed(format!(
                "Failed to bind DNS listener {}: {e}",
                self.config.listen
            ))
        })?;
        let local = socket.local_addr().ok();
        tracing::info!(listen = ?local, upstreams = ?upstreams, "DNS forwarder started");

        let cache = DnsCache::default();
        let registry = self.registry.clone();
        let filter = DnsFilterSets {
            block: std::sync::Arc::new(
                self.config
                    .blocklist
                    .iter()
                    .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
                    .filter(|d| !d.is_empty())
                    .collect(),
            ),
            allow: std::sync::Arc::new(
                self.config
                    .allowlist
                    .iter()
                    .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
                    .filter(|d| !d.is_empty())
                    .collect(),
            ),
        };
        let task = tokio::spawn(forward_loop(
            socket,
            upstreams,
            cache,
            self.config.cache_size,
            self.config.log_queries,
            registry,
            filter,
            self.vpn_proxy.clone(),
        ));

        self.task = Some(task);
        self.local = local;
        self.running = true;
        self.health = HealthStatus::Healthy;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), DriverError> {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
        self.local = None;
        self.running = false;
        self.health = HealthStatus::Unknown;
        tracing::info!("DNS forwarder stopped");
        Ok(())
    }

    async fn restart(&mut self) -> Result<(), DriverError> {
        self.stop().await?;
        self.start().await?;
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        if !self.running {
            return HealthStatus::Unhealthy { reason: 1 };
        }
        if let Some(task) = &self.task {
            if task.is_finished() {
                return HealthStatus::Unhealthy { reason: 2 };
            }
        }
        // UDP listener check (`-u`, not `-t`).
        let port = self
            .local
            .map(|a| a.port())
            .unwrap_or(self.config.listen.port());
        let output = std::process::Command::new(ss_bin())
            .args(["-ulnp", &format!("sport = :{port}")])
            .output();
        match output {
            Ok(out)
                if out.status.success()
                    && String::from_utf8_lossy(&out.stdout).contains(&port.to_string()) =>
            {
                HealthStatus::Healthy
            }
            _ => HealthStatus::Degraded { reason: 1 },
        }
    }
}

impl Drop for DnsForwarderDriver {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_upstream(count: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> SocketAddr {
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener
            .set_nonblocking(true)
            .expect("nonblocking upstream");
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match listener.recv_from(&mut buf) {
                    Ok((_n, peer)) => {
                        count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let response = [0xAB, 0xCD]; // opaque DNS response
                        let _ = listener.send_to(&response[..], peer);
                    }
                    Err(_)
                        if std::io::Error::last_os_error().kind()
                            == std::io::ErrorKind::WouldBlock =>
                    {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        addr
    }

    async fn query_driver(driver: &mut DnsForwarderDriver, query: &[u8]) -> Option<Vec<u8>> {
        driver.start().await.expect("start");
        let local = driver.local_addr().expect("bound address");
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(query, local).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        Some(buf[..n].to_vec())
    }

    #[tokio::test]
    async fn forwards_query_to_upstream() {
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let upstream = mock_upstream(hits.clone());
        let mut driver = DnsForwarderDriver::new(
            DriverId::DnsForwarder,
            DnsForwarderConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstreams: vec![upstream],
                ..DnsForwarderConfig::default()
            },
        );
        let resp = query_driver(
            &mut driver,
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00",
        )
        .await;
        assert_eq!(resp, Some(vec![0xAB, 0xCD]));
        assert_eq!(hits.load(std::sync::atomic::Ordering::Relaxed), 1);
        driver.stop().await.expect("stop");
        assert!(!driver.running);
    }

    #[tokio::test]
    async fn fails_over_to_healthy_upstream() {
        // First upstream is a closed port (immediate error), second answers.
        let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let healthy = mock_upstream(hits.clone());
        let mut driver = DnsForwarderDriver::new(
            DriverId::DnsForwarder,
            DnsForwarderConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstreams: vec![dead, healthy],
                ..DnsForwarderConfig::default()
            },
        );
        let resp = query_driver(&mut driver, b"query").await;
        assert_eq!(resp, Some(vec![0xAB, 0xCD]));
        assert_eq!(hits.load(std::sync::atomic::Ordering::Relaxed), 1);
        driver.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn cache_serves_repeat_query_without_upstream() {
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let upstream = mock_upstream(hits.clone());
        let mut driver = DnsForwarderDriver::new(
            DriverId::DnsForwarder,
            DnsForwarderConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstreams: vec![upstream],
                cache_size: 100,
                ..DnsForwarderConfig::default()
            },
        );
        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        let first = query_driver(&mut driver, query).await;
        assert_eq!(first, Some(vec![0xAB, 0xCD]));
        let second = query_driver(&mut driver, query).await;
        assert_eq!(second, Some(vec![0xAB, 0xCD]));
        // Only the first query reached the upstream; the second hit the cache.
        assert_eq!(hits.load(std::sync::atomic::Ordering::Relaxed), 1);
        driver.stop().await.expect("stop");
    }

    /// A real DNS A query for `obs.example.com` and the matching response
    /// (answer uses a compression pointer to the question name).
    fn obs_query() -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234u16.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
        q.extend_from_slice(b"\x03obs\x07example\x03com\x00");
        q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        q
    }

    fn obs_response() -> Vec<u8> {
        let mut r = obs_query();
        r[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // QR|RD|RA
        r[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
        r.extend_from_slice(&[0xC0, 0x0C]); // pointer to question name
        r.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        r.extend_from_slice(&300u32.to_be_bytes()); // TTL
        r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        r.extend_from_slice(&[203, 0, 113, 42]); // 203.0.113.42
        r
    }

    #[tokio::test]
    async fn forwarded_responses_feed_the_policy_registry() {
        // Upstream answers with a real A record; the driver must parse it and
        // record obs.example.com → [203.0.113.42] in the shared registry,
        // making the observation visible to the flow compiler / B4 observer.
        let addr = std::sync::Arc::new(std::sync::Mutex::new(None::<SocketAddr>));
        let listener = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        *addr.lock().unwrap() = Some(listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match listener.recv_from(&mut buf) {
                    Ok((_n, peer)) => {
                        let _ = listener.send_to(&obs_response(), peer);
                    }
                    Err(_)
                        if std::io::Error::last_os_error().kind()
                            == std::io::ErrorKind::WouldBlock =>
                    {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });

        let registry = DnsRegistry::new();
        let mut driver = DnsForwarderDriver::new(
            DriverId::DnsForwarder,
            DnsForwarderConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstreams: vec![addr.lock().unwrap().unwrap()],
                cache_size: 0, // force an upstream round-trip every query
                ..DnsForwarderConfig::default()
            },
        );
        driver.attach_registry(std::sync::Arc::new(registry.clone()));
        driver.start().await.expect("start");
        let local = driver.local_addr().expect("bound");

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&obs_query(), local).await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf))
            .await
            .expect("response");

        // The observation must reach the shared registry (policy plane).
        let ips = registry
            .resolve("obs.example.com")
            .expect("registry populated from forwarded response");
        assert!(ips.contains(&"203.0.113.42".parse().unwrap()));

        driver.stop().await.expect("stop");
    }

    #[test]
    fn cache_respects_zero_capacity() {
        let cache = DnsCache::default();
        cache.put(b"q".to_vec(), b"r".to_vec(), 0);
        assert!(cache.get(b"q").is_none());
        cache.put(b"q".to_vec(), b"r".to_vec(), 1);
        assert_eq!(cache.get(b"q"), Some(b"r".to_vec()));
    }

    fn sets(
        block: &[&str],
        allow: &[&str],
    ) -> (
        std::sync::Arc<HashSet<String>>,
        std::sync::Arc<HashSet<String>>,
    ) {
        (
            std::sync::Arc::new(block.iter().map(|s| s.to_string()).collect()),
            std::sync::Arc::new(allow.iter().map(|s| s.to_string()).collect()),
        )
    }

    #[test]
    fn classify_block_exact_and_subdomains() {
        let (block, allow) = sets(&["ads.example.com"], &[]);
        assert_eq!(
            classify_domain("ads.example.com", &block, &allow),
            DomainDecision::Block
        );
        assert_eq!(
            classify_domain("x.ads.example.com", &block, &allow),
            DomainDecision::Block
        );
        assert_eq!(
            classify_domain("example.com", &block, &allow),
            DomainDecision::Pass
        );
    }

    #[test]
    fn classify_allowlist_overrides_blocklist() {
        let (block, allow) = sets(&["example.com"], &["safe.example.com"]);
        assert_eq!(
            classify_domain("example.com", &block, &allow),
            DomainDecision::Block
        );
        assert_eq!(
            classify_domain("safe.example.com", &block, &allow),
            DomainDecision::Pass
        );
        assert_eq!(
            classify_domain("deep.safe.example.com", &block, &allow),
            DomainDecision::Pass
        );
    }

    #[test]
    fn classify_unmatched_passes() {
        let (block, allow) = sets(&[], &[]);
        assert_eq!(
            classify_domain("youtube.com", &block, &allow),
            DomainDecision::Pass
        );
    }

    #[test]
    fn nxdomain_echoes_id_and_rcode() {
        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        let resp = nxdomain_response(query);
        assert_eq!(resp[0], 0x12);
        assert_eq!(resp[1], 0x34);
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(resp[3] & 0x0f, 0x03); // NXDOMAIN
        assert_eq!(&resp[6..8], &[0, 0]); // ANCOUNT=0
    }

    #[tokio::test]
    async fn blocked_domain_answered_locally_without_upstream() {
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let upstream = mock_upstream(hits.clone());
        let registry = DnsRegistry::new();
        let mut driver = DnsForwarderDriver::new(
            DriverId::DnsForwarder,
            DnsForwarderConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstreams: vec![upstream],
                blocklist: vec!["ads.example.com".into()],
                ..DnsForwarderConfig::default()
            },
        );
        driver.attach_registry(std::sync::Arc::new(registry.clone()));
        let local = {
            driver.start().await.expect("start");
            driver.local_addr().expect("bound")
        };

        let q = {
            let mut v = Vec::new();
            v.extend_from_slice(&0xABCDu16.to_be_bytes());
            v.extend_from_slice(&0x0100u16.to_be_bytes());
            v.extend_from_slice(&1u16.to_be_bytes());
            v.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            v.extend_from_slice(b"\x03ads\x07example\x03com\x00");
            v.extend_from_slice(&1u16.to_be_bytes());
            v.extend_from_slice(&1u16.to_be_bytes());
            v
        };
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&q, local).await.unwrap();
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf))
            .await
            .expect("response")
            .expect("recv");
        let resp = &buf[..n];
        assert_eq!(resp[0], 0xAB);
        assert_eq!(resp[1], 0xCD);
        assert_eq!(resp[3] & 0x0f, 0x03); // NXDOMAIN
                                          // Never touched the upstream, never polluted the policy registry.
        assert_eq!(hits.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(registry.resolve("ads.example.com").is_none());
        driver.stop().await.expect("stop");
    }

    #[tokio::test]
    async fn allowlist_unblocks_a_subdomain() {
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let upstream = mock_upstream(hits.clone());
        let mut driver = DnsForwarderDriver::new(
            DriverId::DnsForwarder,
            DnsForwarderConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstreams: vec![upstream],
                blocklist: vec!["example.com".into()],
                allowlist: vec!["safe.example.com".into()],
                ..DnsForwarderConfig::default()
            },
        );
        let local = {
            driver.start().await.expect("start");
            driver.local_addr().expect("bound")
        };
        let q = {
            let mut v = Vec::new();
            v.extend_from_slice(&0x1111u16.to_be_bytes());
            v.extend_from_slice(&0x0100u16.to_be_bytes());
            v.extend_from_slice(&1u16.to_be_bytes());
            v.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            v.extend_from_slice(b"\x04safe\x07example\x03com\x00");
            v.extend_from_slice(&1u16.to_be_bytes());
            v.extend_from_slice(&1u16.to_be_bytes());
            v
        };
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&q, local).await.unwrap();
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf))
            .await
            .expect("response")
            .expect("recv");
        let resp = &buf[..n];
        // Forwarded upstream (opaque mock answer), not a local NXDOMAIN.
        assert_eq!(resp, &[0xAB, 0xCD]);
        assert_eq!(hits.load(std::sync::atomic::Ordering::Relaxed), 1);
        driver.stop().await.expect("stop");
    }

    #[test]
    fn test_dns_forwarder_config() {
        let config = DnsForwarderConfig::default();
        assert_eq!(config.listen, "127.0.0.1:53".parse::<SocketAddr>().unwrap());
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.cache_size, 10000);
    }

    #[test]
    fn test_dns_forwarder_driver() {
        let config = DnsForwarderConfig::default();
        let driver = DnsForwarderDriver::new(DriverId::DnsForwarder, config);
        assert_eq!(driver.id(), DriverId::DnsForwarder);
        assert_eq!(driver.name(), "DNS Forwarder");
        assert!(driver.capabilities().contains(Capabilities::DNS));
    }
}
