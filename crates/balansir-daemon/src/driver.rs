use async_trait::async_trait;
use balansir_common::{Capabilities, HealthStatus};
use tracing::info;

pub struct DummyDriver {
    id: String,
    name: String,
    healthy: bool,
}

impl DummyDriver {
    pub fn new(id: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            healthy: true,
        }
    }
}

#[async_trait]
pub trait ComponentDriver: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn capabilities(&self) -> Capabilities;

    async fn start(&mut self) -> Result<(), String>;
    async fn stop(&mut self) -> Result<(), String>;
    async fn restart(&mut self) -> Result<(), String>;
    async fn health_check(&self) -> HealthStatus;
}

#[async_trait]
impl ComponentDriver for DummyDriver {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::TUNNEL | Capabilities::PROXY
    }

    async fn start(&mut self) -> Result<(), String> {
        info!("DummyDriver started: {}", self.name);
        self.healthy = true;
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), String> {
        info!("DummyDriver stopped: {}", self.name);
        self.healthy = false;
        Ok(())
    }

    async fn restart(&mut self) -> Result<(), String> {
        info!("DummyDriver restarted: {}", self.name);
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
        let mut driver = DummyDriver::new("dummy-1", "Test Dummy");

        assert_eq!(driver.id(), "dummy-1");
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
