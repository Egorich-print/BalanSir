//! BalanSir OTA subsystem.
//!
//! Provides signed OTA updates with A/B slot management, atomic boot selection,
//! post-boot health checks, and automatic rollback.

pub mod daemon;
pub mod health;
pub mod manifest;
pub mod migrate;
pub mod slot;

use balansir_common::Result;

/// OTA subsystem version.
pub const OTA_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the OTA subsystem.
pub fn init() -> Result<()> {
    tracing::info!("BalanSir OTA subsystem v{}", OTA_VERSION);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ota_version_present() {
        assert!(!OTA_VERSION.is_empty());
    }
}
