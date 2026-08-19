//! Component driver trait (ADR-011). Legacy lifecycle/health/factory layers
//! were removed: real transports run through their own managers (xray_manager,
//! dns, upnp) which construct drivers directly.

use async_trait::async_trait;
use balansir_common::{Capabilities, DriverError, DriverId, HealthStatus};

/// Component driver base trait.
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
