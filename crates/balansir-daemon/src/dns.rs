use async_trait::async_trait;
use balansir_common::{
    Capabilities, DriverId, HealthStatus,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::driver::ComponentDriver;

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
            upstreams: vec![
                "1.1.1.1:53".parse().unwrap(),
                "8.8.8.8:53".parse().unwrap(),
            ],
            doh: false,
            dot: false,
            cache_size: 10000,
            log_queries: false,
        }
    }
}

/// DNS forwarder driver
pub struct DnsForwarderDriver {
    id: DriverId,
    config: DnsForwarderConfig,
    running: bool,
    health: HealthStatus,
}

impl DnsForwarderDriver {
    /// Create a new DNS forwarder driver
    pub fn new(id: DriverId, config: DnsForwarderConfig) -> Self {
        Self {
            id,
            config,
            running: false,
            health: HealthStatus::Unknown,
        }
    }

    fn generate_config(&self) -> String {
        let upstreams: Vec<String> = self.config.upstreams.iter().map(|u| {
            format!("\"{}\"", u)
        }).collect();

        format!(
            r#"{{
  "listen": "{}",
  "upstreams": [{}],
  "doh": {},
  "dot": {},
  "cache_size": {},
  "log_queries": {}
}}"#,
            self.config.listen,
            upstreams.join(", "),
            self.config.doh,
            self.config.dot,
            self.config.cache_size,
            self.config.log_queries,
        )
    }

    fn start_process(&self) -> Result<(), String> {
        // For now, just log that we would start a DNS forwarder
        // In production, this would start a real DNS forwarder
        tracing::info!("DNS forwarder would listen on {}", self.config.listen);
        Ok(())
    }

    fn stop_process(&self) -> Result<(), String> {
        // Stop DNS forwarder process
        tracing::info!("DNS forwarder stopped");
        Ok(())
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

    async fn start(&mut self) -> Result<(), String> {
        tracing::info!("Starting DNS forwarder on {}", self.config.listen);

        self.start_process()?;

        self.running = true;
        self.health = HealthStatus::Healthy;

        tracing::info!("DNS forwarder started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), String> {
        tracing::info!("Stopping DNS forwarder");

        self.stop_process()?;

        self.running = false;
        self.health = HealthStatus::Unknown;

        tracing::info!("DNS forwarder stopped");
        Ok(())
    }

    async fn restart(&mut self) -> Result<(), String> {
        self.stop().await?;
        self.start().await?;
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        if !self.running {
            return HealthStatus::Unhealthy { reason: 1 };
        }

        // Check if port is listening
        let output = std::process::Command::new("ss")
            .args(["-tlnp", &format!("sport = :{}", self.config.listen.port())])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains(&self.config.listen.port().to_string()) {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Degraded { reason: 1 }
                }
            }
            _ => HealthStatus::Degraded { reason: 1 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let driver = DnsForwarderDriver::new(DriverId::new(6), config);
        assert_eq!(driver.id(), DriverId::new(6));
        assert_eq!(driver.name(), "DNS Forwarder");
        assert!(driver.capabilities().contains(Capabilities::DNS));
    }

    #[test]
    fn test_dns_forwarder_config_generation() {
        let config = DnsForwarderConfig::default();
        let driver = DnsForwarderDriver::new(DriverId::new(6), config);
        let config_str = driver.generate_config();

        assert!(config_str.contains("127.0.0.1:53"));
        assert!(config_str.contains("1.1.1.1:53"));
        assert!(config_str.contains("8.8.8.8:53"));
    }
}
