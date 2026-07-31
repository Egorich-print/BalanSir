use async_trait::async_trait;
use balansir_common::{Capabilities, HealthStatus};
use tracing::info;

pub struct WireGuardDriver {
    id: String,
    name: String,
    interface: String,
    private_key: Option<String>,
    address: Option<String>,
    running: bool,
}

impl WireGuardDriver {
    pub fn new(id: &str, name: &str, interface: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            interface: interface.to_string(),
            private_key: None,
            address: None,
            running: false,
        }
    }

    pub fn set_private_key(&mut self, key: &str) {
        self.private_key = Some(key.to_string());
    }

    pub fn set_address(&mut self, addr: &str) {
        self.address = Some(addr.to_string());
    }

    fn check_interface_exists(&self) -> bool {
        std::path::Path::new(&format!("/sys/class/net/{}", self.interface)).exists()
    }
}

#[async_trait]
impl super::driver::ComponentDriver for WireGuardDriver {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::TUNNEL
    }

    async fn start(&mut self) -> Result<(), String> {
        info!("WireGuardDriver starting: {}", self.name);

        // In real implementation:
        // 1. Create WireGuard interface
        // 2. Set private key
        // 3. Set address
        // 4. Bring interface up

        self.running = true;
        info!("WireGuardDriver started: {}", self.name);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), String> {
        info!("WireGuardDriver stopping: {}", self.name);

        // In real implementation:
        // 1. Bring interface down
        // 2. Delete interface

        self.running = false;
        info!("WireGuardDriver stopped: {}", self.name);
        Ok(())
    }

    async fn restart(&mut self) -> Result<(), String> {
        info!("WireGuardDriver restarting: {}", self.name);
        self.stop().await?;
        self.start().await?;
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        if !self.running {
            return HealthStatus::Unhealthy { reason: 1 };
        }

        // In real implementation, also check:
        // 1. Interface exists in /sys/class/net/
        // 2. Peer connectivity
        // 3. Latency and packet loss

        HealthStatus::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::ComponentDriver;

    #[tokio::test]
    async fn test_wireguard_driver() {
        let mut driver = WireGuardDriver::new("wg-1", "Test WireGuard", "wg0");

        assert_eq!(driver.id(), "wg-1");
        assert_eq!(driver.name(), "Test WireGuard");

        driver.start().await.unwrap();
        assert_eq!(driver.health_check().await, HealthStatus::Healthy);

        driver.stop().await.unwrap();
        assert_eq!(
            driver.health_check().await,
            HealthStatus::Unhealthy { reason: 1 }
        );
    }
}
