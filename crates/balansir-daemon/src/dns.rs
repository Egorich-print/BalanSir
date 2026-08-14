use async_trait::async_trait;
use balansir_common::{Capabilities, DriverError, DriverId, HealthStatus};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::driver::ComponentDriver;

fn ss_bin() -> std::path::PathBuf {
    balansir_common::paths::resolve_bin_or_default("ss")
}

/// Per-upstream forward timeout. A failed or slow upstream is skipped in
/// favor of the next one, so a single dead server cannot stall the network.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);
/// Fixed TTL applied to cached responses (we relay opaque DNS messages and do
/// not re-write TTLs; 30s is a safe floor for typical A/AAAA records).
const CACHE_TTL: Duration = Duration::from_secs(30);

/// DNS forwarder configuration
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
        }
    }
}

/// Small bounded query-response cache. Keyed by the raw query bytes (no
/// parsing, no injection surface); entries expire after `CACHE_TTL`.
#[derive(Default)]
struct DnsCache(Mutex<HashMap<Vec<u8>, (Vec<u8>, Instant)>>);

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
async fn forward_query(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    sock.connect(upstream).await.ok()?;
    sock.send(query).await.ok()?;
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(FORWARD_TIMEOUT, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

/// UDP DNS forwarding loop. Answers queries from `socket`, failing over
/// across `upstreams` in round-robin order, and caches responses.
async fn forward_loop(
    socket: UdpSocket,
    upstreams: Vec<SocketAddr>,
    cache: DnsCache,
    cache_size: usize,
    log_queries: bool,
) {
    let mut round_robin = 0usize;
    let mut buf = vec![0u8; 4096];
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

        let response = match cache.get(&query) {
            Some(r) => Some(r),
            None => {
                let mut response = None;
                for offset in 0..upstreams.len() {
                    let idx = (round_robin + offset) % upstreams.len();
                    if let Some(r) = forward_query(&query, upstreams[idx]).await {
                        response = Some(r);
                        break;
                    }
                }
                round_robin = (round_robin + 1).max(1) % upstreams.len();
                if let Some(r) = &response {
                    cache.put(query.clone(), r.clone(), cache_size);
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
        }
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
        let task = tokio::spawn(forward_loop(
            socket,
            upstreams,
            cache,
            self.config.cache_size,
            self.config.log_queries,
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
                    Ok((n, peer)) => {
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

    #[test]
    fn cache_respects_zero_capacity() {
        let cache = DnsCache::default();
        cache.put(b"q".to_vec(), b"r".to_vec(), 0);
        assert!(cache.get(b"q").is_none());
        cache.put(b"q".to_vec(), b"r".to_vec(), 1);
        assert_eq!(cache.get(b"q"), Some(b"r".to_vec()));
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
