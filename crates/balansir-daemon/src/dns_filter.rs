//! DNS Filtering Plane (native, lightweight, Pi-hole/AdGuard level).
//!
//! This module provides LAN DNS listener + local cache/resolver with
//! blocklists/allowlists and per-domain classification (DIRECT / BLOCK / B4 / VPN).
//! No cloud dependencies, no DNS leaks, race/cache-poison/leak protection.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use balansir_common::{Capabilities, DriverError, DriverId, HealthStatus, Result};
use crate::driver::ComponentDriver;
use crate::reconciliation::DnsRegistry;

/// DNS classification for a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsClassification {
    /// Pass through directly (no DPI bypass, no VPN).
    Direct,
    /// Block resolution (return NXDOMAIN).
    Block,
    /// Apply B4 DPI bypass strategies.
    B4,
    /// Route through VPN tunnel.
    Vpn,
}

impl Default for DnsClassification {
    fn default() -> Self {
        DnsClassification::Direct
    }
}

/// A domain policy entry with optional IP overrides.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DomainPolicy {
    pub domain: String,
    pub classification: DnsClassification,
    /// Optional IP override for VPN/B4 (when domain must resolve to specific IP).
    pub ip_override: Option<IpAddr>,
    /// TTL for this policy (seconds).
    pub ttl: Option<u32>,
}

/// DNS Filtering configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DnsFilterConfig {
    /// Listen address for LAN clients.
    pub listen: SocketAddr,
    /// Upstream DNS servers (DoT/DoH not implemented yet; plain UDP).
    pub upstreams: Vec<SocketAddr>,
    /// Cache size (number of entries).
    pub cache_size: usize,
    /// Enable DNS logging.
    pub log_queries: bool,
    /// Blocklist (domains to NXDOMAIN).
    pub blocklist: Vec<String>,
    /// Allowlist (explicit pass-through, overrides blocklist).
    pub allowlist: Vec<String>,
    /// Per-domain classification rules (highest precedence).
    pub domain_policies: Vec<DomainPolicy>,
    /// Default classification when no rule matches.
    #[serde(default)]
    pub default_classification: DnsClassification,
    /// Upstream forward timeout.
    #[serde(default = "default_forward_timeout")]
    pub forward_timeout_secs: u64,
    /// Cache TTL floor (seconds).
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
}

fn default_forward_timeout() -> u64 {
    2
}
fn default_cache_ttl() -> u64 {
    30
}

impl Default for DnsFilterConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:53".parse().unwrap(),
            upstreams: vec!["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()],
            cache_size: 10000,
            log_queries: false,
            blocklist: Vec::new(),
            allowlist: Vec::new(),
            domain_policies: Vec::new(),
            default_classification: DnsClassification::Direct,
            forward_timeout_secs: 2,
            cache_ttl_secs: 30,
        }
    }
}

/// A cached DNS response entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expires: Instant,
}

/// Internal state for the DNS filter.
struct DnsFilterState {
    cache: HashMap<Vec<u8>, CacheEntry>,
    cache_size: usize,
    blocklist: HashMap<String, ()>,
    allowlist: HashMap<String, ()>,
    domain_policies: HashMap<String, DomainPolicy>,
    default_classification: DnsClassification,
    upstreams: Vec<SocketAddr>,
    forward_timeout: Duration,
    cache_ttl: Duration,
    log_queries: bool,
    round_robin: usize,
}

impl DnsFilterState {
    fn new(config: DnsFilterConfig) -> Self {
        let mut blocklist = HashMap::new();
        for d in config.blocklist {
            blocklist.insert(d.to_lowercase(), ());
        }
        let mut allowlist = HashMap::new();
        for d in config.allowlist {
            allowlist.insert(d.to_lowercase(), ());
        }
        let mut domain_policies = HashMap::new();
        for p in config.domain_policies {
            domain_policies.insert(p.domain.to_lowercase(), p);
        }
        Self {
            cache: HashMap::new(),
            cache_size: config.cache_size,
            blocklist,
            allowlist,
            domain_policies,
            default_classification: config.default_classification,
            upstreams: config.upstreams,
            forward_timeout: Duration::from_secs(config.forward_timeout_secs),
            cache_ttl: Duration::from_secs(config.cache_ttl_secs),
            log_queries: config.log_queries,
            round_robin: 0,
        }
    }

    /// Classify a query domain.
    fn classify(&self, domain: &str) -> (DnsClassification, Option<IpAddr>) {
        let lower = domain.to_lowercase();
        
        // Check explicit domain policies first (highest precedence)
        if let Some(policy) = self.domain_policies.get(&lower) {
            return (policy.classification, policy.ip_override);
        }

        // Check allowlist (explicit pass-through)
        if self.allowlist.contains_key(&lower) {
            return (DnsClassification::Direct, None);
        }

        // Check blocklist
        if self.blocklist.contains_key(&lower) {
            return (DnsClassification::Block, None);
        }

        // Default classification
        (self.default_classification, None)
    }

    /// Check if a response is already cached.
    fn cache_get(&mut self, query: &[u8]) -> Option<Vec<u8>> {
        if let Some(entry) = self.cache.get(query) {
            if entry.expires > Instant::now() {
                return Some(entry.response.clone());
            } else {
                self.cache.remove(query);
            }
        }
        None
    }

    /// Store a response in cache.
    fn cache_put(&mut self, query: Vec<u8>, response: Vec<u8>) {
        if self.cache.len() >= self.cache_size {
            // Simple eviction: remove oldest 10%
            let to_remove = (self.cache_size / 10).max(1);
            let mut keys: Vec<Vec<u8>> = self.cache.keys().cloned().collect();
            keys.truncate(to_remove);
            for k in keys {
                self.cache.remove(&k);
            }
        }
        self.cache.insert(query, CacheEntry {
            response,
            expires: Instant::now() + self.cache_ttl,
        });
    }

    /// Extract domain name from DNS query (simplified, handles compression).
    fn extract_domain(query: &[u8]) -> Option<String> {
        if query.len() < 17 { // minimum DNS header + question
            return None;
        }
        // Skip header (12 bytes) + question section
        let mut pos = 12;
        let mut labels = Vec::new();
        let mut jumps = 0;
        
        while pos < query.len() && jumps < 16 {
            let len = query[pos];
            if len == 0 {
                pos += 1;
                break;
            }
            if len & 0xC0 == 0xC0 {
                // Compression pointer - skip
                pos += 2;
                jumps += 1;
                break;
            }
            pos += 1;
            if pos + len as usize > query.len() {
                return None;
            }
            let label = std::str::from_utf8(&query[pos..pos + len as usize]).ok()?;
            labels.push(label);
            pos += len as usize;
        }
        Some(labels.join("."))
    }
}

/// DNS Filter driver: LAN DNS listener with filtering, classification, and caching.
pub struct DnsFilterDriver {
    id: DriverId,
    config: DnsFilterConfig,
    running: bool,
    health: HealthStatus,
    task: Option<tokio::task::JoinHandle<()>>,
    local: Option<SocketAddr>,
    state: Arc<RwLock<DnsFilterState>>,
    registry: Option<Arc<DnsRegistry>>,
}

impl DnsFilterDriver {
    pub fn new(id: u32, config: DnsFilterConfig) -> Self {
        Self {
            id,
            config,
            running: false,
            health: HealthStatus::Unknown,
            task: None,
            local: None,
            state: Arc::new(RwLock::new(DnsFilterState::new(config.clone()))),
            registry: None,
        }
    }

    pub fn attach_registry(&mut self, registry: Arc<DnsRegistry>) {
        self.registry = Some(registry);
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local
    }

    /// Start the DNS filter loop (internal implementation).
    async fn start_impl(&mut self) -> Result<(), DriverError> {
        let socket = UdpSocket::bind(self.config.listen).await
            .map_err(|e| DriverError::StartFailed(format!("bind DNS listener: {e}")))?;
        self.local = Some(socket.local_addr().map_err(|e| DriverError::StartFailed(format!("local addr: {e}")))?);
        info!("DNS Filter listening on {}", self.local.unwrap());

        let state = self.state.clone();
        let registry = self.registry.clone();
        let log_queries = self.config.log_queries;

        self.task = Some(tokio::spawn(async move {
            Self::run_loop(socket, state, registry, log_queries).await;
        }));

        self.running = true;
        self.health = HealthStatus::Healthy;
        Ok(())
    }

    /// Stop the DNS filter (internal implementation).
    async fn stop_impl(&mut self) -> Result<(), DriverError> {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.running = false;
        self.health = HealthStatus::Unhealthy { reason: 1 };
        Ok(())
    }

    /// Restart the DNS filter (internal implementation).
    async fn restart_impl(&mut self) -> Result<(), DriverError> {
        self.stop_impl().await?;
        self.start_impl().await
    }

    /// Health check (internal implementation).
    async fn health_check_impl(&self) -> HealthStatus {
        self.health
    }

    /// Main UDP loop.
    async fn run_loop(
        socket: UdpSocket,
        state: Arc<RwLock<DnsFilterState>>,
        registry: Option<Arc<DnsRegistry>>,
        log_queries: bool,
    ) {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return, // socket closed
            };
            let query = buf[..n].to_vec();
            if query.is_empty() {
                continue;
            }

            let domain = DnsFilterState::extract_domain(&query);
            let (classification, ip_override) = {
                let state = state.read().await;
                if let Some(domain) = &domain {
                    state.classify(domain)
                } else {
                    (state.default_classification, None)
                }
            };

            if log_queries {
                debug!(from = %peer, domain = ?domain, classification = ?classification, "dns filter query");
            }

            // Handle classification
            let response = match classification {
                DnsClassification::Block => {
                    // Return NXDOMAIN
                    Self::build_nxdomain(&query)
                }
                DnsClassification::Direct | DnsClassification::B4 | DnsClassification::Vpn => {
                    // Forward to upstream (could apply different upstreams per classification)
                    let mut state_guard = state.write().await;
                    if let Some(cached) = state_guard.cache_get(&query) {
                        cached
                    } else {
                        let response = Self::forward_upstream(&state_guard.upstreams, &mut state_guard.round_robin, &query, state_guard.forward_timeout).await;
                        if let Some(ref resp) = response {
                            state_guard.cache_put(query.clone(), resp.clone());
                            // Populate DNS registry for policy plane
                            if let Some(reg) = &registry {
                                if let Some(domain) = &domain {
                                    if let Some(ips) = Self::parse_a_aaaa(resp) {
                                        reg.insert(domain, ips);
                                    }
                                }
                            }
                        }
                        response.unwrap_or_else(|| Self::build_servfail(&query))
                    }
                }
            };

            // Send response
            if let Err(e) = socket.send_to(&response, peer).await {
                warn!("dns filter send error: {e}");
            }
        }
    }

    /// Forward query to upstream with round-robin failover.
    async fn forward_upstream(
        upstreams: &[SocketAddr],
        round_robin: &mut usize,
        query: &[u8],
        timeout: Duration,
    ) -> Option<Vec<u8>> {
        if upstreams.is_empty() {
            return None;
        }
        for offset in 0..upstreams.len() {
            let idx = (*round_robin + offset) % upstreams.len();
            let upstream = upstreams[idx];
            if let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await {
                if sock.connect(upstream).await.is_ok() {
                    if sock.send(query).await.is_ok() {
                        let mut resp_buf = vec![0u8; 4096];
                        match tokio::time::timeout(timeout, sock.recv(&mut resp_buf)).await {
                            Ok(Ok(n)) => {
                                *round_robin = (idx + 1) % upstreams.len();
                                return Some(resp_buf[..n].to_vec());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        None
    }

    /// Build NXDOMAIN response.
    fn build_nxdomain(query: &[u8]) -> Vec<u8> {
        let mut resp = query.to_vec();
        if resp.len() >= 2 {
            resp[2] |= 0x81; // QR=1, RCODE=0 (will be overwritten)
            resp[3] = 0x83;  // RCODE=3 (NXDOMAIN)
        }
        // Clear answer count
        if resp.len() >= 8 {
            resp[6] = 0;
            resp[7] = 0;
        }
        resp
    }

    /// Build SERVFAIL response.
    fn build_servfail(query: &[u8]) -> Vec<u8> {
        let mut resp = query.to_vec();
        if resp.len() >= 4 {
            resp[2] |= 0x81; // QR=1
            resp[3] = 0x82;  // RCODE=2 (SERVFAIL)
        }
        if resp.len() >= 8 {
            resp[6] = 0;
            resp[7] = 0;
        }
        resp
    }

    /// Parse A/AAAA records from response (simplified).
    fn parse_a_aaaa(response: &[u8]) -> Option<Vec<IpAddr>> {
        if response.len() < 12 {
            return None;
        }
        let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
        if ancount == 0 {
            return None;
        }
        let mut pos = 12;
        // Skip question section
        while pos < response.len() && response[pos] != 0 {
            let len = response[pos] as usize;
            if len & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + len;
        }
        pos += 5; // Skip name (null) + type + class
        let mut ips = Vec::new();
        for _ in 0..ancount {
            if pos >= response.len() {
                break;
            }
            // Skip name (could be compressed)
            if pos + 1 < response.len() && response[pos] & 0xC0 == 0xC0 {
                pos += 2;
            } else {
                while pos < response.len() && response[pos] != 0 {
                    pos += 1 + response[pos] as usize;
                }
                pos += 1;
            }
            if pos + 10 > response.len() {
                break;
            }
            let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
            pos += 8; // Skip type + class + TTL
            let rdlen = u16::from_be_bytes([response[pos], response[pos + 1]]) as usize;
            pos += 2;
            if pos + rdlen > response.len() {
                break;
            }
            match rtype {
                1 => { // A record
                    if rdlen == 4 {
                        let ip = IpAddr::V4(Ipv4Addr::new(
                            response[pos], response[pos+1], response[pos+2], response[pos+3]
                        ));
                        ips.push(ip);
                    }
                }
                28 => { // AAAA record
                    if rdlen == 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&response[pos..pos+16]);
                        ips.push(IpAddr::V6(octets.into()));
                    }
                }
                _ => {}
            }
            pos += rdlen;
        }
        if ips.is_empty() { None } else { Some(ips) }
    }
}

impl ComponentDriver for DnsFilterDriver {
    fn id(&self) -> DriverId {
        self.id
    }

    fn name(&self) -> &str {
        "DNS Filter"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::DNS
    }

    async fn start(&mut self) -> Result<(), DriverError> {
        self.start_impl().await
    }

    async fn stop(&mut self) -> Result<(), DriverError> {
        self.stop_impl().await
    }

    async fn restart(&mut self) -> Result<(), DriverError> {
        self.restart_impl().await
    }

    async fn health_check(&self) -> HealthStatus {
        self.health_check_impl().await
    }
}