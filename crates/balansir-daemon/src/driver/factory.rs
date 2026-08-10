//! Daemon-side `DriverFactory` glue: resolves a `DriverId` to a concrete
//! `ComponentDriver` from its typed `DriverConfig` (M3.5).
//!
//! The factory is configuration-driven: `build` looks up the driver's typed
//! config in the registry and constructs the matching concrete driver. A
//! driver with no config (or an unknown id) fails honestly with
//! `ConfigInvalid`, which the lifecycle FSM tracks as a `Failed` slot — never
//! a fabricated removal.

use async_trait::async_trait;
use balansir_common::{DriverError, DriverId};

use crate::driver::config::{DriverConfig, DriverConfigRegistry};
use crate::driver::lifecycle::DriverFactory;
use crate::driver::ComponentDriver;

/// Configuration-driven factory (M3.5).
///
/// Owns the typed `DriverId → DriverConfig` registry and constructs concrete
/// drivers from it. The registry is source-agnostic: it can be populated from
/// a profile/config file today or a dynamic control plane later, without
/// changing the driver contract.
pub struct ConfiguredFactory {
    registry: DriverConfigRegistry,
}

impl ConfiguredFactory {
    pub fn new(registry: DriverConfigRegistry) -> Self {
        Self { registry }
    }

    pub fn empty() -> Self {
        Self {
            registry: DriverConfigRegistry::new(),
        }
    }
}

impl ConfiguredFactory {
    fn build_driver(
        &self,
        id: DriverId,
        config: &DriverConfig,
    ) -> Result<Box<dyn ComponentDriver>, DriverError> {
        match config {
            #[cfg(feature = "wireguard")]
            DriverConfig::WireGuard(c) => Ok(Box::new(crate::wireguard::WireGuardDriver::new(
                id,
                c.clone(),
            ))),
            #[cfg(feature = "amneziawg")]
            DriverConfig::AmneziaWG(c) => Ok(Box::new(crate::amneziawg::AmneziaWGDriver::new(
                id,
                c.clone(),
            ))),
            #[cfg(feature = "xray")]
            DriverConfig::Xray(c) => Ok(Box::new(crate::xray::XrayDriver::new(id, c.clone()))),
            #[cfg(feature = "hysteria")]
            DriverConfig::Hysteria(c) => Ok(Box::new(crate::hysteria::Hysteria2Driver::new(
                id,
                c.clone(),
            ))),
            #[cfg(feature = "b4")]
            DriverConfig::B4(c) => Ok(Box::new(crate::b4::B4Driver::new(id, c.clone()))),
            #[cfg(feature = "dns")]
            DriverConfig::Dns(c) => {
                Ok(Box::new(crate::dns::DnsForwarderDriver::new(id, c.clone())))
            }
        }
    }
}

#[async_trait]
impl DriverFactory for ConfiguredFactory {
    async fn build(
        &self,
        id: DriverId,
        _fingerprint: u64,
    ) -> Result<Box<dyn ComponentDriver>, DriverError> {
        let config = self
            .registry
            .get(id)
            .ok_or_else(|| DriverError::ConfigInvalid(format!("no config for driver {:?}", id)))?;
        self.build_driver(id, config)
    }
}

/// Backward-compatible alias for a factory with an empty registry. Kept so the
/// existing lifecycle wiring (which constructs a factory at daemon start)
/// continues to compile; `main.rs` swaps in a `ConfiguredFactory` with real
/// configs.
pub type NotYetWiredFactory = ConfiguredFactory;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::config::DriverConfig;
    use balansir_common::Capabilities;

    fn b4_config() -> DriverConfig {
        DriverConfig::B4(crate::b4::B4Config {
            mode: crate::b4::B4Mode::Transparent,
            ports: vec![80, 443],
            strategies: vec![crate::b4::B4Strategy::TtlDisorientation],
            upstream: None,
        })
    }

    #[tokio::test]
    async fn factory_constructs_b4_driver_from_config() {
        let mut registry = DriverConfigRegistry::new();
        registry.insert(DriverId::B4, b4_config());
        let factory = ConfiguredFactory::new(registry);

        let driver = match factory.build(DriverId::B4, 1).await {
            Ok(d) => d,
            Err(e) => panic!("B4 must construct, got: {e:?}"),
        };
        assert_eq!(driver.id(), DriverId::B4);
        assert_eq!(driver.name(), "B4");
        assert!(driver
            .capabilities()
            .contains(Capabilities::PACKET_PROCESSOR));
    }

    #[tokio::test]
    async fn factory_without_config_fails_honestly() {
        let factory = ConfiguredFactory::empty();
        let err = match factory.build(DriverId::B4, 1).await {
            Err(e) => e,
            Ok(_) => panic!("empty factory must not construct a driver"),
        };
        assert!(matches!(err, DriverError::ConfigInvalid(_)));
    }

    /// M3.5: B4 start is environment-dependent. In ordinary CI there is no `b4`
    /// binary, so start must fail explicitly (BinaryNotFound) — never a
    /// fabricated Active. The lifecycle FSM tracks this as a Failed slot.
    #[tokio::test]
    async fn b4_start_fails_explicitly_without_environment() {
        let mut registry = DriverConfigRegistry::new();
        registry.insert(DriverId::B4, b4_config());
        let factory = ConfiguredFactory::new(registry);

        let mut driver = factory.build(DriverId::B4, 1).await.unwrap();
        let result = driver.start().await;
        match result {
            Err(DriverError::BinaryNotFound(_)) | Err(DriverError::StartFailed(_)) => {}
            other => panic!("B4 start must fail without the b4 binary, got: {other:?}"),
        }
    }
}
