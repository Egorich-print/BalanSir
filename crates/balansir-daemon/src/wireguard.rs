use async_trait::async_trait;
use balansir_common::{Capabilities, DriverError, DriverId, HealthStatus};
use serde::{Deserialize, Serialize};

use crate::driver::ComponentDriver;

/// WireGuard configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    pub interface: String,
    pub private_key: Option<String>,
    pub listen_port: Option<u16>,
    pub address: Option<String>,
    pub peers: Vec<WireGuardPeer>,
}

/// WireGuard peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

/// WireGuard driver
pub struct WireGuardDriver {
    id: DriverId,
    config: WireGuardConfig,
    running: bool,
    health: HealthStatus,
}

impl WireGuardDriver {
    /// Create a new WireGuard driver
    pub fn new(id: DriverId, config: WireGuardConfig) -> Self {
        Self {
            id,
            config,
            running: false,
            health: HealthStatus::Unknown,
        }
    }

    fn check_interface(&self) -> bool {
        std::path::Path::new(&format!("/sys/class/net/{}", self.config.interface)).exists()
    }

    fn create_interface(&self) -> Result<(), DriverError> {
        let output = std::process::Command::new("ip")
            .args(["link", "add", &self.config.interface, "type", "wireguard"])
            .output()
            .map_err(|e| DriverError::StartFailed(format!("Failed to create interface: {}", e)))?;

        if !output.status.success() {
            return Err(DriverError::InterfaceError(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        Ok(())
    }

    fn configure_interface(&self) -> Result<(), DriverError> {
        if let Some(ref addr) = self.config.address {
            let output = std::process::Command::new("ip")
                .args(["addr", "add", addr, "dev", &self.config.interface])
                .output()
                .map_err(|e| DriverError::StartFailed(format!("Failed to set address: {}", e)))?;

            if !output.status.success() {
                return Err(DriverError::InterfaceError(
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ));
            }
        }

        let output = std::process::Command::new("ip")
            .args(["link", "set", &self.config.interface, "up"])
            .output()
            .map_err(|e| {
                DriverError::StartFailed(format!("Failed to bring up interface: {}", e))
            })?;

        if !output.status.success() {
            return Err(DriverError::InterfaceError(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        Ok(())
    }

    fn delete_interface(&self) -> Result<(), DriverError> {
        let output = std::process::Command::new("ip")
            .args(["link", "del", &self.config.interface])
            .output()
            .map_err(|e| DriverError::StopFailed(format!("Failed to delete interface: {}", e)))?;

        if !output.status.success() {
            return Ok(());
        }

        Ok(())
    }
}

#[async_trait]
impl ComponentDriver for WireGuardDriver {
    fn id(&self) -> DriverId {
        self.id
    }

    fn name(&self) -> &str {
        "WireGuard"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::TUNNEL
    }

    async fn start(&mut self) -> Result<(), DriverError> {
        tracing::info!("Starting WireGuard driver: {}", self.config.interface);

        self.create_interface()?;
        self.configure_interface()?;

        self.running = true;
        self.health = HealthStatus::Healthy;

        tracing::info!("WireGuard driver started: {}", self.config.interface);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), DriverError> {
        tracing::info!("Stopping WireGuard driver: {}", self.config.interface);

        self.delete_interface()?;

        self.running = false;
        self.health = HealthStatus::Unknown;

        tracing::info!("WireGuard driver stopped: {}", self.config.interface);
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

        if !self.check_interface() {
            return HealthStatus::Degraded { reason: 1 };
        }

        HealthStatus::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_config() {
        let config = WireGuardConfig {
            interface: "wg0".to_string(),
            private_key: Some("test-key".to_string()),
            listen_port: Some(51820),
            address: Some("10.0.0.1/24".to_string()),
            peers: vec![WireGuardPeer {
                public_key: "peer-key".to_string(),
                endpoint: Some("vpn.example.com:51820".to_string()),
                allowed_ips: vec!["0.0.0.0/0".to_string()],
                persistent_keepalive: Some(25),
            }],
        };

        let driver = WireGuardDriver::new(DriverId::WireGuard, config);
        assert_eq!(driver.id(), DriverId::WireGuard);
        assert_eq!(driver.name(), "WireGuard");
        assert!(driver.capabilities().contains(Capabilities::TUNNEL));
    }
}
