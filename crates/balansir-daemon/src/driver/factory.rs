//! Daemon-side `DriverFactory` glue: resolves a `DriverId` to a concrete
//! `ComponentDriver` from the config loaded for that driver.
//!
//! Today the daemon has no config→driver mapping (configs arrive via profile /
//! plan work in M3.4/M3.5). The factory therefore returns a typed
//! `DriverError::MissingConfig` for any resolved driver until that glue lands,
//! letting the lifecycle manager exercise its state machine end-to-end and
//! treat an unconfigd driver exactly like a failed start (never a removal).

use async_trait::async_trait;
use balansir_common::{DriverError, DriverId};

use crate::driver::lifecycle::DriverFactory;
use crate::driver::ComponentDriver;

/// Factory whose build step fails until the daemon wires real driver configs
/// (M3.4 plan engine / M3.5 async drivers). Failures flow through the state
/// machine as tracked `Failed` slots, proving the failure != removal boundary.
pub struct NotYetWiredFactory;

#[async_trait]
impl DriverFactory for NotYetWiredFactory {
    async fn build(
        &self,
        _id: DriverId,
        _fingerprint: u64,
    ) -> Result<Box<dyn ComponentDriver>, DriverError> {
        Err(DriverError::ConfigInvalid(
            "driver configuration not wired yet (M3.4/M3.5)".to_string(),
        ))
    }
}
