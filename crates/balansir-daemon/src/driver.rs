use async_trait::async_trait;
use balansir_common::{Capabilities, DriverId, HealthStatus};

/// Component driver trait
#[async_trait]
pub trait ComponentDriver: Send + Sync {
    fn id(&self) -> DriverId;
    fn name(&self) -> &str;
    fn capabilities(&self) -> Capabilities;

    async fn start(&mut self) -> Result<(), String>;
    async fn stop(&mut self) -> Result<(), String>;
    async fn restart(&mut self) -> Result<(), String>;
    async fn health_check(&self) -> HealthStatus;
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

    async fn start(&mut self) -> Result<(), String> {
        tracing::info!("DummyDriver started: {}", self.name);
        self.healthy = true;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), String> {
        tracing::info!("DummyDriver stopped: {}", self.name);
        self.healthy = false;
        Ok(())
    }

    async fn restart(&mut self) -> Result<(), String> {
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
        let mut driver = DummyDriver::new(DriverId::new(99), "Test Dummy");

        assert_eq!(driver.id(), DriverId::new(99));
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
