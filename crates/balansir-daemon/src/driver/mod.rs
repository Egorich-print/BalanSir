use async_trait::async_trait;
use balansir_common::{Capabilities, DriverError, DriverId, HealthStatus};

pub mod factory;
pub mod health;
pub mod lifecycle;

/// Component driver trait (base for all drivers)
#[async_trait]
pub trait ComponentDriver: Send + Sync {
    fn id(&self) -> DriverId;
    fn name(&self) -> &str;
    fn capabilities(&self) -> Capabilities;

    async fn start(&mut self) -> Result<(), DriverError>;
    async fn stop(&mut self) -> Result<(), DriverError>;
    async fn restart(&mut self) -> Result<(), DriverError>;
    async fn health_check(&self) -> HealthStatus;
}

/// Layer 3 Tunnel Driver (WireGuard, AmneziaWG)
/// Creates and manages kernel network interfaces
#[async_trait]
pub trait Layer3Driver: ComponentDriver {
    /// Get the network interface name
    fn interface_name(&self) -> &str;

    /// Get the interface index (if available)
    async fn interface_index(&self) -> Option<u32>;

    /// Check if interface is up
    async fn is_interface_up(&self) -> bool;

    /// Get interface statistics (bytes in/out, packets)
    async fn interface_stats(&self) -> Option<InterfaceStats>;
}

/// Layer 7 Proxy Driver (Xray, Hysteria, Shadowsocks)
/// Manages local socket listeners and TPROXY
#[async_trait]
pub trait Layer7Driver: ComponentDriver {
    /// Get the SOCKS5 proxy endpoint
    fn socks_endpoint(&self) -> Option<std::net::SocketAddr>;

    /// Get the HTTP proxy endpoint
    fn http_endpoint(&self) -> Option<std::net::SocketAddr>;

    /// Get the TPROXY port (if using transparent proxy)
    fn tproxy_port(&self) -> Option<u16>;

    /// Get proxy statistics (connections, bytes transferred)
    async fn proxy_stats(&self) -> Option<ProxyStats>;
}

/// Interface statistics for L3 drivers
#[derive(Debug, Clone, Default)]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// Proxy statistics for L7 drivers
#[derive(Debug, Clone, Default)]
pub struct ProxyStats {
    pub active_connections: u32,
    pub total_connections: u64,
    pub bytes_uploaded: u64,
    pub bytes_downloaded: u64,
}

/// Dummy driver for testing
pub struct DummyDriver {
    id: DriverId,
    name: String,
    healthy: bool,
}

impl DummyDriver {
    pub fn new(id: DriverId, name: &str) -> Self {
        Self {
            id,
            name: name.to_string(),
            healthy: true,
        }
    }
}

#[async_trait]
impl ComponentDriver for DummyDriver {
    fn id(&self) -> DriverId {
        self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::TUNNEL | Capabilities::PROXY
    }

    async fn start(&mut self) -> Result<(), DriverError> {
        tracing::info!("DummyDriver started: {}", self.name);
        self.healthy = true;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), DriverError> {
        tracing::info!("DummyDriver stopped: {}", self.name);
        self.healthy = false;
        Ok(())
    }

    async fn restart(&mut self) -> Result<(), DriverError> {
        tracing::info!("DummyDriver restarted: {}", self.name);
        self.stop().await?;
        self.start().await?;
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        if self.healthy {
            HealthStatus::Healthy
        } else {
            HealthStatus::Unhealthy { reason: 1 }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dummy_driver() {
        let mut driver = DummyDriver::new(DriverId::Custom(99), "Test Dummy");

        assert_eq!(driver.id(), DriverId::Custom(99));
        assert_eq!(driver.name(), "Test Dummy");

        driver.start().await.unwrap();
        assert_eq!(driver.health_check().await, HealthStatus::Healthy);

        driver.stop().await.unwrap();
        assert_eq!(
            driver.health_check().await,
            HealthStatus::Unhealthy { reason: 1 }
        );
    }
}
