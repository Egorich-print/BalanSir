// crates/balansir-control/src/provider.rs

use crate::error::{ControlError, ControlResult};
use crate::traits::{DesiredProvider, StateProvider};
use async_trait::async_trait;
use balansir_common::{
    Action, ActualState, DesiredDriver, DesiredRule, DesiredState, DriverAction, DriverId,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// TOML shape for a desired-state config file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DesiredConfig {
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub drivers: Vec<DriverConfig>,
}

impl DesiredConfig {
    /// Read and parse a desired-state config file (strict compile).
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> ControlResult<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ControlError::DesiredProvider(format!("read {:?}: {e}", path.as_ref())))?;
        let config: Self = toml::from_str(&content).map_err(|e| {
            ControlError::DesiredProvider(format!("parse {:?}: {e}", path.as_ref()))
        })?;
        Ok(config)
    }
}

/// One rule entry in the config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub id: u32,
    pub action: String,
    #[serde(default)]
    pub priority: u32,
}

/// One driver entry in the config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverConfig {
    pub id: String,
    pub action: String,
}

/// Loads desired state from a TOML file.
///
/// The file format is intentionally thin (a projection over `DesiredState`);
/// profiles and overrides compose later via a `CompositeDesiredProvider`.
#[derive(Debug, Clone)]
pub struct ConfigDesiredProvider {
    path: PathBuf,
}

impl ConfigDesiredProvider {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

fn parse_action(s: &str) -> ControlResult<Action> {
    let lower = s.to_ascii_lowercase();
    match lower.as_str() {
        "allow" => Ok(Action::Allow),
        "block" => Ok(Action::Block),
        "reject" => Ok(Action::Reject),
        "log" => Ok(Action::Log),
        _ => Err(ControlError::DesiredProvider(format!(
            "unknown action: {s}"
        ))),
    }
}

fn parse_driver_id(s: &str) -> ControlResult<DriverId> {
    let lower = s.to_ascii_lowercase();
    let id = match lower.as_str() {
        "wireguard" => DriverId::WireGuard,
        "amneziawg" => DriverId::AmneziaWG,
        "xray" => DriverId::Xray,
        "hysteria" => DriverId::Hysteria,
        "b4" => DriverId::B4,
        "dns" | "dnsforwarder" => DriverId::DnsForwarder,
        _ => {
            return Err(ControlError::DesiredProvider(format!(
                "unknown driver: {s}"
            )))
        }
    };
    Ok(id)
}

fn parse_driver_action(s: &str) -> ControlResult<DriverAction> {
    let lower = s.to_ascii_lowercase();
    match lower.as_str() {
        "start" => Ok(DriverAction::Start),
        "stop" => Ok(DriverAction::Stop),
        "restart" => Ok(DriverAction::Restart),
        _ => Err(ControlError::DesiredProvider(format!(
            "unknown driver action: {s}"
        ))),
    }
}

/// Compile a `DesiredConfig` into a `DesiredState`, rejecting any entry that
/// does not parse. A single malformed rule or driver aborts the whole compile
/// so a malformed reload is always rejected atomically (ADR-010).
impl TryFrom<DesiredConfig> for DesiredState {
    type Error = ControlError;

    fn try_from(config: DesiredConfig) -> Result<Self, Self::Error> {
        let rules = config
            .rules
            .into_iter()
            .map(|r| {
                Ok(DesiredRule {
                    id: r.id,
                    action: parse_action(&r.action)?,
                    priority: r.priority,
                })
            })
            .collect::<Result<Vec<_>, ControlError>>()?;

        let drivers = config
            .drivers
            .into_iter()
            .map(|d| {
                Ok(DesiredDriver {
                    id: parse_driver_id(&d.id)?,
                    action: parse_driver_action(&d.action)?,
                })
            })
            .collect::<Result<Vec<_>, ControlError>>()?;

        Ok(Self { rules, drivers })
    }
}

#[async_trait]
impl DesiredProvider for ConfigDesiredProvider {
    async fn desired(&self) -> ControlResult<DesiredState> {
        let data = tokio::fs::read(&self.path).await.map_err(|e| {
            ControlError::DesiredProvider(format!("read {}: {e}", self.path.display()))
        })?;

        let config: DesiredConfig = toml::from_str(std::str::from_utf8(&data).map_err(|e| {
            ControlError::DesiredProvider(format!("utf8 decode {}: {e}", self.path.display()))
        })?)
        .map_err(|e| {
            ControlError::DesiredProvider(format!("parse {}: {e}", self.path.display()))
        })?;

        DesiredState::try_from(config)
    }
}

/// A desired-state provider that always fails. Useful in tests to exercise the
/// coordinator's failure path.
#[derive(Debug, Clone, Copy)]
pub struct MissingDesiredProvider;

#[async_trait]
impl DesiredProvider for MissingDesiredProvider {
    async fn desired(&self) -> ControlResult<DesiredState> {
        Err(ControlError::DesiredProvider("no configured source".into()))
    }
}

/// In-memory desired state provider (used for tests and API overrides).
#[derive(Debug, Clone)]
pub struct MemoryDesiredProvider {
    state: DesiredState,
}

impl MemoryDesiredProvider {
    pub fn new(state: DesiredState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl DesiredProvider for MemoryDesiredProvider {
    async fn desired(&self) -> ControlResult<DesiredState> {
        Ok(self.state.clone())
    }
}

/// In-memory actual-state provider (used for tests and simulators).
#[derive(Debug, Clone, Default)]
pub struct MemoryStateProvider {
    state: ActualState,
}

impl MemoryStateProvider {
    pub fn new(state: ActualState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl StateProvider for MemoryStateProvider {
    async fn actual(&self) -> ControlResult<ActualState> {
        Ok(self.state.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenient_config_compiles_fully() {
        let config = DesiredConfig {
            rules: vec![
                RuleConfig {
                    id: 1,
                    action: "block".into(),
                    priority: 100,
                },
                RuleConfig {
                    id: 2,
                    action: "allow".into(),
                    priority: 50,
                },
            ],
            drivers: vec![DriverConfig {
                id: "wireguard".into(),
                action: "start".into(),
            }],
        };
        let state = DesiredState::try_from(config).unwrap();
        assert_eq!(state.rules.len(), 2);
        assert_eq!(state.drivers.len(), 1);
    }

    #[test]
    fn single_bad_action_rejects_whole_config() {
        let config = DesiredConfig {
            rules: vec![
                RuleConfig {
                    id: 1,
                    action: "block".into(),
                    priority: 100,
                },
                RuleConfig {
                    id: 2,
                    action: "nonsense".into(),
                    priority: 50,
                },
            ],
            drivers: vec![],
        };
        let err = DesiredState::try_from(config).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("unknown action"));
    }

    #[test]
    fn bad_driver_rejects_whole_config() {
        let config = DesiredConfig {
            rules: vec![RuleConfig {
                id: 1,
                action: "allow".into(),
                priority: 10,
            }],
            drivers: vec![DriverConfig {
                id: "not-a-driver".into(),
                action: "start".into(),
            }],
        };
        assert!(DesiredState::try_from(config).is_err());
    }
}
