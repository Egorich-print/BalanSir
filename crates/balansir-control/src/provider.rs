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
    /// Policy-level semantics (P1, ADR-019).
    #[serde(default)]
    pub policy: PolicyConfig,
}

/// Policy-level semantics for a config (P1, ADR-019).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// What an *empty* rule set means. `Pass` (default) installs nothing
    /// (fail-open, current behavior). `Drop` installs a single terminal
    /// fail-closed rule so an empty config does not silently pass everything.
    #[serde(default)]
    pub empty_config_action: EmptyConfigAction,
}

/// Action for an empty rule set (P1, ADR-019).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmptyConfigAction {
    /// Install nothing (fail-open). Current behavior.
    #[default]
    Pass,
    /// Install a single terminal drop (fail-closed).
    Drop,
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleConfig {
    pub id: u32,
    pub action: String,
    #[serde(default)]
    pub priority: u32,
    /// Optional flow matcher (A3). Any field absent means "any".
    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    #[serde(default)]
    pub protocol: Option<String>,
    /// Domain matcher (A3): the daemon resolves this to concrete `dst_ip`s at
    /// reload time via the DNS flow compiler.
    #[serde(default)]
    pub dst_domain: Option<String>,
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

/// Parse an L4 protocol selector: `tcp`, `udp`, or an IANA protocol number.
fn parse_protocol(s: &str) -> ControlResult<u8> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        _ => s
            .parse::<u8>()
            .map_err(|_| ControlError::DesiredProvider(format!("unknown protocol: {s}"))),
    }
}

/// Compile a `DesiredConfig` into a `DesiredState`, rejecting any entry that
/// does not parse. A single malformed rule or driver aborts the whole compile
/// so a malformed reload is always rejected atomically (ADR-010).
impl TryFrom<DesiredConfig> for DesiredState {
    type Error = ControlError;

    fn try_from(config: DesiredConfig) -> Result<Self, Self::Error> {
        let mut rules = config
            .rules
            .into_iter()
            .map(|r| {
                let flow = if r.src_ip.is_none()
                    && r.dst_ip.is_none()
                    && r.src_port.is_none()
                    && r.dst_port.is_none()
                    && r.protocol.is_none()
                    && r.dst_domain.is_none()
                {
                    None
                } else {
                    Some(balansir_common::FlowCriteria {
                        src_ip: r
                            .src_ip
                            .map(|s| {
                                s.parse::<std::net::IpAddr>().map_err(|e| {
                                    ControlError::DesiredProvider(format!(
                                        "invalid src_ip {}: {e}",
                                        s
                                    ))
                                })
                            })
                            .transpose()?,
                        dst_ip: r
                            .dst_ip
                            .map(|s| {
                                s.parse::<std::net::IpAddr>().map_err(|e| {
                                    ControlError::DesiredProvider(format!(
                                        "invalid dst_ip {}: {e}",
                                        s
                                    ))
                                })
                            })
                            .transpose()?,
                        src_port: r.src_port,
                        dst_port: r.dst_port,
                        protocol: r.protocol.as_deref().map(parse_protocol).transpose()?,
                        dst_domain: r.dst_domain,
                    })
                };
                Ok(DesiredRule {
                    id: r.id,
                    action: parse_action(&r.action)?,
                    priority: r.priority,
                    flow,
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

        // P1 (ADR-019): fail-closed semantics for an empty rule set. When the
        // compiled rules are empty and the config asks for `Drop`, append a
        // single terminal drop so an empty config cannot silently pass
        // everything. The executor stays non-authoritative — this is a
        // desired-state compile decision, not a mechanism default.
        if rules.is_empty() && config.policy.empty_config_action == EmptyConfigAction::Drop {
            rules.push(DesiredRule {
                id: balansir_common::FAIL_CLOSED_RULE_ID,
                action: Action::Block,
                priority: 0,
                flow: None,
            });
        }

        Ok(Self {
            rules,
            drivers,
            qos: Vec::new(),
        })
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
                    ..Default::default()
                },
                RuleConfig {
                    id: 2,
                    action: "allow".into(),
                    priority: 50,
                    ..Default::default()
                },
            ],
            drivers: vec![DriverConfig {
                id: "wireguard".into(),
                action: "start".into(),
            }],
            policy: Default::default(),
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
                    ..Default::default()
                },
                RuleConfig {
                    id: 2,
                    action: "nonsense".into(),
                    priority: 50,
                    ..Default::default()
                },
            ],
            drivers: vec![],
            policy: Default::default(),
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
                ..Default::default()
            }],
            drivers: vec![DriverConfig {
                id: "not-a-driver".into(),
                action: "start".into(),
            }],
            policy: Default::default(),
        };
        assert!(DesiredState::try_from(config).is_err());
    }

    /// P1 (ADR-019): default is fail-open — an empty config installs nothing.
    #[test]
    fn empty_config_defaults_to_pass() {
        let config = DesiredConfig::default();
        let state = DesiredState::try_from(config).unwrap();
        assert!(state.rules.is_empty());
    }

    /// P1 (ADR-019): fail-closed — an empty config with `empty_config_action =
    /// "drop"` compiles to a single terminal drop rule.
    #[test]
    fn empty_config_fail_closed_installs_terminal_drop() {
        let config = DesiredConfig {
            policy: PolicyConfig {
                empty_config_action: EmptyConfigAction::Drop,
            },
            ..Default::default()
        };
        let state = DesiredState::try_from(config).unwrap();
        assert_eq!(state.rules.len(), 1);
        assert_eq!(state.rules[0].id, balansir_common::FAIL_CLOSED_RULE_ID);
        assert_eq!(state.rules[0].action, Action::Block);
        assert!(state.rules[0].flow.is_none());
    }

    /// P1 (ADR-019): fail-closed only applies to an *empty* rule set — a config
    /// with rules is unchanged.
    #[test]
    fn fail_closed_does_not_touch_non_empty_config() {
        let config = DesiredConfig {
            rules: vec![RuleConfig {
                id: 1,
                action: "allow".into(),
                priority: 10,
                ..Default::default()
            }],
            policy: PolicyConfig {
                empty_config_action: EmptyConfigAction::Drop,
            },
            ..Default::default()
        };
        let state = DesiredState::try_from(config).unwrap();
        assert_eq!(state.rules.len(), 1);
        assert_eq!(state.rules[0].id, 1);
    }

    /// P1 (ADR-019): the TOML spelling is `[policy] empty_config_action =
    /// "drop"` (lowercase), parsed strictly.
    #[test]
    fn empty_config_action_parses_from_toml() {
        let config: DesiredConfig =
            toml::from_str("[policy]\nempty_config_action = \"drop\"\n").unwrap();
        assert_eq!(config.policy.empty_config_action, EmptyConfigAction::Drop);

        let pass: DesiredConfig = toml::from_str("").unwrap();
        assert_eq!(pass.policy.empty_config_action, EmptyConfigAction::Pass);
    }
}
