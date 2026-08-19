//! BalanSir OTA subsystem.
//!
//! A/B slot image installer (write the inactive slot via `dd`). The update
//! discovery/verify/post-boot loop and config migrations were dead code and
//! were removed — the CLI only installs an image provided by the operator.

pub mod daemon;
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
