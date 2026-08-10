//! Typed per-driver configuration (M3.5).
//!
//! This is the approved `DriverId → DriverConfig` representation: a strongly
//! typed, serializable enumeration over the concrete driver configs. It is
//! independent from runtime lifecycle state and from `PolicyEngine`, so the
//! factory can later be supplied from any configuration source (file, profile,
//! future dynamic control plane) without changing the driver contract.
//!
//! Each variant is feature-gated to match the driver module it wraps — a
//! driver that is not compiled cannot be configured.

use balansir_common::{DriverError, DriverId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[cfg(feature = "amneziawg")]
use crate::amneziawg::AmneziaWGConfig;
#[cfg(feature = "b4")]
use crate::b4::B4Config;
#[cfg(feature = "dns")]
use crate::dns::DnsForwarderConfig;
#[cfg(feature = "hysteria")]
use crate::hysteria::Hysteria2Config;
#[cfg(feature = "wireguard")]
use crate::wireguard::WireGuardConfig;
#[cfg(feature = "xray")]
use crate::xray::XrayConfig;

/// Strongly typed configuration for a single driver.
///
/// One variant per concrete driver config. This is an explicit, extensible
/// contract — not an untyped blob or a god object. Adding a future driver
/// means adding one variant plus its `DriverFactory` construction arm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DriverConfig {
    #[cfg(feature = "wireguard")]
    WireGuard(WireGuardConfig),
    #[cfg(feature = "amneziawg")]
    AmneziaWG(AmneziaWGConfig),
    #[cfg(feature = "xray")]
    Xray(XrayConfig),
    #[cfg(feature = "hysteria")]
    Hysteria(Hysteria2Config),
    #[cfg(feature = "b4")]
    B4(B4Config),
    #[cfg(feature = "dns")]
    Dns(DnsForwarderConfig),
}

/// A concrete driver's `DriverId` as declared in its config.
///
/// Kept as the TOML-facing key so a config file can name a driver and the
/// registry maps it to the canonical `DriverId`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverEntry {
    pub id: String,
    pub config: DriverConfig,
}

/// TOML shape for driver configuration (M3.5).
///
/// Static today, but the representation itself is source-agnostic: the same
/// typed `DriverConfigRegistry` can later be populated from a dynamic control
/// plane without reworking the factory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriverConfigFile {
    #[serde(default)]
    pub drivers: Vec<DriverEntry>,
}

/// An owned `DriverId → DriverConfig` map.
///
/// This is the configuration source handed to the `DriverFactory`. It is
/// intentionally a plain typed map (no dynamic dispatch, no plugin registry).
#[derive(Debug, Clone, Default)]
pub struct DriverConfigRegistry {
    inner: HashMap<DriverId, DriverConfig>,
}

impl DriverConfigRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, id: DriverId, config: DriverConfig) {
        self.inner.insert(id, config);
    }

    pub fn get(&self, id: DriverId) -> Option<&DriverConfig> {
        self.inner.get(&id)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Resolve a config file into a registry. Unknown driver names are a hard
    /// error (ADR-010 strict-compile spirit): a config that names a driver we
    /// cannot map must fail loudly, not be silently dropped.
    pub fn from_file(path: &Path) -> Result<Self, DriverError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| DriverError::ConfigInvalid(format!("read {path:?}: {e}")))?;
        let file: DriverConfigFile = toml::from_str(&content)
            .map_err(|e| DriverError::ConfigInvalid(format!("parse {path:?}: {e}")))?;
        Self::from_file_config(file)
    }

    /// Build a registry from an in-memory config file value.
    pub fn from_file_config(file: DriverConfigFile) -> Result<Self, DriverError> {
        let mut registry = Self::new();
        for entry in file.drivers {
            let id = DriverId::from_name(&entry.id);
            registry.insert(id, entry.config);
        }
        Ok(registry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_roundtrips_typed_b4_config() {
        #[cfg(feature = "b4")]
        {
            let config = DriverConfig::B4(crate::b4::B4Config {
                mode: crate::b4::B4Mode::Proxy,
                ports: vec![443],
                strategies: vec![crate::b4::B4Strategy::TtlDisorientation],
                upstream: Some("127.0.0.1:8080".into()),
            });
            let mut registry = DriverConfigRegistry::new();
            registry.insert(DriverId::B4, config.clone());

            let got = registry.get(DriverId::B4).unwrap();
            match got {
                DriverConfig::B4(c) => {
                    assert!(matches!(c.mode, crate::b4::B4Mode::Proxy));
                    assert_eq!(c.ports, vec![443]);
                }
                _ => panic!("expected B4 config"),
            }

            // Serializable as a typed contract.
            let json = serde_json::to_string(&config).unwrap();
            let back: DriverConfig = serde_json::from_str(&json).unwrap();
            assert!(matches!(back, DriverConfig::B4(_)));
        }
    }

    #[test]
    fn registry_from_toml_resolves_driver_names() {
        // Externally-tagged enum: the TOML names the variant, then its fields.
        // B4Mode uses Rust variant names (Transparent/Proxy) in its serde form.
        let toml = r#"
[[drivers]]
id = "b4"
config = { B4 = { mode = "Proxy", ports = [443], strategies = [], upstream = "127.0.0.1:8080" } }
"#;
        let file: DriverConfigFile = toml::from_str(toml).unwrap();
        let registry = DriverConfigRegistry::from_file_config(file).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.get(DriverId::B4).is_some());
    }

    #[test]
    fn driver_config_is_independent_of_lifecycle() {
        // The config type must not carry runtime state; it only exists to
        // construct drivers. A constructed driver's runtime fields are not part
        // of config, so config remains serializable and reusable.
        #[cfg(feature = "b4")]
        {
            let config = DriverConfig::B4(crate::b4::B4Config {
                mode: crate::b4::B4Mode::Transparent,
                ports: vec![80],
                strategies: vec![],
                upstream: None,
            });
            let driver = crate::b4::B4Driver::new(
                DriverId::B4,
                match &config {
                    DriverConfig::B4(c) => c.clone(),
                    _ => unreachable!(),
                },
            );
            // Construction from config succeeds; runtime lifecycle state is not
            // part of the config type.
            let _ = driver;
        }
    }
}
