use async_trait::async_trait;
use balansir_common::{
    Action, ActionResult, ActionType, Capabilities, DriverId, ExecutorCapabilities, HealthStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

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

    fn create_interface(&self) -> Result<(), String> {
        let output = std::process::Command::new("ip")
            .args(["link", "add", &self.config.interface, "type", "wireguard"])
            .output()
            .map_err(|e| format!("Failed to create interface: {}", e))?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }

        Ok(())
    }

    fn configure_interface(&self) -> Result<(), String> {
        if let Some(ref addr) = self.config.address {
            let output = std::process::Command::new("ip")
                .args(["addr", "add", addr, "dev", &self.config.interface])
                .output()
                .map_err(|e| format!("Failed to set address: {}", e))?;

            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr).to_string());
            }
        }

        let output = std::process::Command::new("ip")
            .args(["link", "set", &self.config.interface, "up"])
            .output()
            .map_err(|e| format!("Failed to bring up interface: {}", e))?;

        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).to_string());
        }

        Ok(())
    }

    fn delete_interface(&self) -> Result<(), String> {
        let output = std::process::Command::new("ip")
            .args(["link", "del", &self.config.interface])
            .output()
            .map_err(|e| format!("Failed to delete interface: {}", e))?;

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

    async fn start(&mut self) -> Result<(), String> {
        tracing::info!("Starting WireGuard driver: {}", self.config.interface);

        self.create_interface()?;
        self.configure_interface()?;

        self.running = true;
        self.health = HealthStatus::Healthy;

        tracing::info!("WireGuard driver started: {}", self.config.interface);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), String> {
        tracing::info!("Stopping WireGuard driver: {}", self.config.interface);

        self.delete_interface()?;

        self.running = false;
        self.health = HealthStatus::Unknown;

        tracing::info!("WireGuard driver stopped: {}", self.config.interface);
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

        if !self.check_interface() {
            return HealthStatus::Degraded { reason: 1 };
        }

        HealthStatus::Healthy
    }
}

/// WireGuard executor - executes WireGuard-specific actions
pub struct WireGuardExecutor {
    capabilities: ExecutorCapabilities,
    drivers: Mutex<HashMap<DriverId, WireGuardDriver>>,
}

impl Default for WireGuardExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl WireGuardExecutor {
    /// Create a new WireGuard executor
    pub fn new() -> Self {
        Self {
            capabilities: ExecutorCapabilities {
                supported_actions: vec![ActionType::Forward],
                max_rules: 64,
                max_fwmarks: 0,
                max_route_tables: 0,
            },
            drivers: Mutex::new(HashMap::new()),
        }
    }

    /// Add a WireGuard driver
    pub fn add_driver(&self, driver: WireGuardDriver) {
        let mut drivers = self.drivers.lock().unwrap_or_else(|e| e.into_inner());
        drivers.insert(driver.id(), driver);
    }

    /// Get capabilities
    pub fn capabilities(&self) -> &ExecutorCapabilities {
        &self.capabilities
    }

    /// Check if action type is supported
    pub fn supports(&self, action_type: ActionType) -> bool {
        self.capabilities.supported_actions.contains(&action_type)
    }

    /// Execute an action
    pub async fn execute(&self, request: &balansir_common::ActionRequest) -> ActionResult {
        match request.action {
            Action::Forward { driver } => {
                // Check if driver exists and get status
                let driver_status = {
                    let drivers = self.drivers.lock().unwrap_or_else(|e| e.into_inner());
                    drivers.get(&driver).map(|d| d.running)
                };

                match driver_status {
                    Some(true) => ActionResult::AlreadyApplied,
                    Some(false) => {
                        // Start driver outside of lock
                        let start_result = {
                            let mut drivers = self.drivers.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(wg_driver) = drivers.get_mut(&driver) {
                                // Can't await while holding lock, so we'll do sync start
                                match wg_driver.create_interface() {
                                    Ok(()) => {
                                        match wg_driver.configure_interface() {
                                            Ok(()) => {
                                                wg_driver.running = true;
                                                Ok(())
                                            }
                                            Err(e) => Err(e),
                                        }
                                    }
                                    Err(e) => Err(e),
                                }
                            } else {
                                Err("Driver not found".to_string())
                            }
                        };

                        match start_result {
                            Ok(()) => ActionResult::Applied {
                                execution_time_us: 0,
                                rule_id: None,
                            },
                            Err(e) => ActionResult::Failed {
                                error: balansir_common::ActionError::Unknown,
                                message: Some(e),
                            },
                        }
                    }
                    None => ActionResult::Failed {
                        error: balansir_common::ActionError::DriverNotAvailable(driver),
                        message: None,
                    },
                }
            }
            _ => ActionResult::Unsupported {
                action_type: request.action.action_type(),
            },
        }
    }

    /// Get rule count
    pub fn rule_count(&self) -> u32 {
        let drivers = self.drivers.lock().unwrap();
        drivers.len() as u32
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

        let driver = WireGuardDriver::new(DriverId::WIREGUARD, config);
        assert_eq!(driver.id(), DriverId::WIREGUARD);
        assert_eq!(driver.name(), "WireGuard");
        assert!(driver.capabilities().contains(Capabilities::TUNNEL));
    }

    #[test]
    fn test_wireguard_executor_capabilities() {
        let executor = WireGuardExecutor::new();
        assert!(executor.supports(ActionType::Forward));
        assert!(!executor.supports(ActionType::Block));
    }
}
