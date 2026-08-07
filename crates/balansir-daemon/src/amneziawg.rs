use async_trait::async_trait;
use balansir_common::{Capabilities, DriverError, DriverId, HealthStatus};
use serde::{Deserialize, Serialize};

use crate::driver::ComponentDriver;

fn ip_bin() -> std::path::PathBuf {
    balansir_common::paths::resolve_bin_or_default("ip")
}

fn lsmod_bin() -> std::path::PathBuf {
    balansir_common::paths::resolve_bin_or_default("lsmod")
}

/// AmneziaWG configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmneziaWGConfig {
    pub interface: String,
    pub private_key: Option<String>,
    pub listen_port: Option<u16>,
    pub address: Option<String>,
    pub peers: Vec<AmneziaWGPeer>,
    pub obfuscation: ObfuscationConfig,
}

/// AmneziaWG peer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmneziaWGPeer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

/// Obfuscation parameters for AmneziaWG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationConfig {
    /// Junk packet count
    pub jc: u32,
    /// Junk packet min size
    pub jmin: u32,
    /// Junk packet max size
    pub jmax: u32,
    /// Init packet junk size
    pub s1: u32,
    /// Response packet junk size
    pub s2: u32,
    /// Init packet magic header
    pub h1: u32,
    /// Response packet magic header
    pub h2: u32,
    /// Transport packet magic header
    pub h3: u32,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            jc: 3,
            jmin: 10,
            jmax: 50,
            s1: 15,
            s2: 15,
            h1: 3847294,
            h2: 8374592,
            h3: 2847592,
        }
    }
}

/// AmneziaWG driver
pub struct AmneziaWGDriver {
    id: DriverId,
    config: AmneziaWGConfig,
    running: bool,
    health: HealthStatus,
}

impl AmneziaWGDriver {
    /// Create a new AmneziaWG driver
    pub fn new(id: DriverId, config: AmneziaWGConfig) -> Self {
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
        // Check if amneziawg kernel module is loaded
        let output = std::process::Command::new(lsmod_bin())
            .output()
            .map_err(|e| DriverError::StartFailed(format!("Failed to check modules: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains("amneziawg") {
            return Err(DriverError::StartFailed(
                "AmneziaWG kernel module not loaded".into(),
            ));
        }

        let output = std::process::Command::new(ip_bin())
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
            let output = std::process::Command::new(ip_bin())
                .args(["addr", "add", addr, "dev", &self.config.interface])
                .output()
                .map_err(|e| DriverError::StartFailed(format!("Failed to set address: {}", e)))?;

            if !output.status.success() {
                return Err(DriverError::InterfaceError(
                    String::from_utf8_lossy(&output.stderr).to_string(),
                ));
            }
        }

        let output = std::process::Command::new(ip_bin())
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
        let output = std::process::Command::new(ip_bin())
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
impl ComponentDriver for AmneziaWGDriver {
    fn id(&self) -> DriverId {
        self.id
    }

    fn name(&self) -> &str {
        "AmneziaWG"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::TUNNEL
    }

    async fn start(&mut self) -> Result<(), DriverError> {
        tracing::info!("Starting AmneziaWG driver: {}", self.config.interface);

        self.create_interface()?;
        self.configure_interface()?;

        self.running = true;
        self.health = HealthStatus::Healthy;

        tracing::info!("AmneziaWG driver started: {}", self.config.interface);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), DriverError> {
        tracing::info!("Stopping AmneziaWG driver: {}", self.config.interface);

        self.delete_interface()?;

        self.running = false;
        self.health = HealthStatus::Unknown;

        tracing::info!("AmneziaWG driver stopped: {}", self.config.interface);
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
    fn test_amneziawg_config() {
        let config = AmneziaWGConfig {
            interface: "awg0".to_string(),
            private_key: Some("test-key".to_string()),
            listen_port: Some(48243),
            address: Some("10.0.0.1/24".to_string()),
            peers: vec![AmneziaWGPeer {
                public_key: "peer-key".to_string(),
                endpoint: Some("vpn.example.com:48243".to_string()),
                allowed_ips: vec!["0.0.0.0/0".to_string()],
                persistent_keepalive: Some(25),
            }],
            obfuscation: ObfuscationConfig::default(),
        };

        let driver = AmneziaWGDriver::new(DriverId::B4, config);
        assert_eq!(driver.id(), DriverId::B4);
        assert_eq!(driver.name(), "AmneziaWG");
        assert!(driver.capabilities().contains(Capabilities::TUNNEL));
    }

    #[test]
    fn test_obfuscation_config() {
        let config = ObfuscationConfig::default();
        assert_eq!(config.jc, 3);
        assert_eq!(config.jmin, 10);
        assert_eq!(config.jmax, 50);
    }
}
