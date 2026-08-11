//! B4 configuration loading (P7.1, ADR-024).
//!
//! B4 policy is authored in its own TOML file, separate from the desired-state
//! config, so it stays a daemon-side concern and never enters the reconcile
//! wire contract. The format:
//!
//! ```toml
//! [engine]
//! enabled = true
//! max_attempts = 3
//!
//! [[flows]]
//! domain = "example.com"
//! capabilities = ["mtu", "dns_path"]
//! fail = "STRICT"
//! allow_direct = true
//! allow_tunnel = false
//! ```

use crate::b4_engine::policy::B4Policy;
use crate::b4_engine::state::B4EngineConfig;
use serde::{Deserialize, Serialize};

/// TOML shape for the B4 config file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct B4Toml {
    #[serde(default)]
    pub engine: B4EngineToml,
    /// Flows are flat in TOML (a list under `[[flows]]`), with profile fields
    /// inlined for ergonomics.
    #[serde(default)]
    pub flows: Vec<B4FlowToml>,
}

/// A B4 policy entry as written in TOML (flat profile fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct B4FlowToml {
    pub domain: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub fail: String,
    #[serde(default = "default_true")]
    pub allow_direct: bool,
    #[serde(default)]
    pub allow_tunnel: bool,
}

impl B4FlowToml {
    fn to_rule(&self) -> Result<crate::b4_engine::policy::B4FlowRule, String> {
        use crate::b4_engine::policy::{B4Capability, B4FailSemantic, B4FlowRule, B4Profile};
        let mut capabilities = Vec::new();
        for c in &self.capabilities {
            match c.to_ascii_lowercase().as_str() {
                "mtu" => capabilities.push(B4Capability::Mtu),
                "dns_path" | "dnspath" => capabilities.push(B4Capability::DnsPath),
                other => return Err(format!("unknown b4 capability: {other}")),
            }
        }
        let fail = match self.fail.to_ascii_uppercase().as_str() {
            "" | "STRICT" => B4FailSemantic::Strict,
            "SAFE" => B4FailSemantic::Safe,
            "DEFAULT" => B4FailSemantic::Default,
            other => return Err(format!("unknown b4 fail semantic: {other}")),
        };
        Ok(B4FlowRule {
            domain: self.domain.clone(),
            profile: B4Profile {
                capabilities,
                fail,
                allow_direct: self.allow_direct,
                allow_tunnel: self.allow_tunnel,
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct B4EngineToml {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
}

impl Default for B4EngineToml {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts: 3,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_attempts() -> u32 {
    3
}

impl B4Toml {
    /// Parse B4 config from a TOML string (strict).
    pub fn parse(content: &str) -> Result<Self, String> {
        toml::from_str(content).map_err(|e| format!("b4 config parse error: {e}"))
    }

    /// Load from a file path.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let path = path.as_ref();
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("b4 config read {path:?}: {e}"))?;
        Self::parse(&content)
    }

    /// The engine config for this file.
    pub fn engine_config(&self) -> B4EngineConfig {
        B4EngineConfig {
            max_attempts: self.engine.max_attempts,
            enabled: self.engine.enabled,
        }
    }

    /// The policy table for this file, converting flat TOML flows.
    pub fn policy(&self) -> Result<B4Policy, String> {
        let mut flows = Vec::new();
        for f in &self.flows {
            flows.push(f.to_rule()?);
        }
        Ok(B4Policy { flows })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_engine_and_flows() {
        let toml = r#"
[engine]
enabled = true
max_attempts = 5

[[flows]]
domain = "example.com"
capabilities = ["mtu", "dns_path"]
fail = "SAFE"
allow_direct = true
allow_tunnel = false
"#;
        let cfg = B4Toml::parse(toml).unwrap();
        assert!(cfg.engine.enabled);
        assert_eq!(cfg.engine.max_attempts, 5);
        let policy = cfg.policy().unwrap();
        assert_eq!(policy.flows.len(), 1);
        let p = policy.profile_for("example.com");
        assert_eq!(p.fail, crate::b4_engine::policy::B4FailSemantic::Safe);
        assert!(p.allow_direct);
        assert!(!p.allow_tunnel);
        assert_eq!(cfg.engine_config().max_attempts, 5);
    }

    #[test]
    fn defaults_are_sane() {
        let cfg = B4Toml::parse("").unwrap();
        assert!(cfg.engine.enabled);
        assert_eq!(cfg.engine.max_attempts, 3);
        assert!(cfg.policy().unwrap().flows.is_empty());
    }

    #[test]
    fn malformed_config_is_rejected() {
        assert!(B4Toml::parse("[[flows]]\ncapabilities = 42\n").is_err());
    }

    #[test]
    fn unknown_capability_is_rejected() {
        let toml = "[[flows]]\ndomain = \"x.com\"\ncapabilities = [\"magic\"]\n";
        let cfg = B4Toml::parse(toml).unwrap();
        assert!(cfg.policy().is_err());
    }
}
