//! DPI-bypass configuration (profiles/sets).
//!
//! Authored as TOML in the style of b4 "sets": named profiles each with a
//! list of domains and the strategies applied to their traffic.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::strategies::{EngineConfig, Profile, Strategy};

/// Top-level TOML configuration for the b4 engine.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct B4Config {
    /// Kernel NFQUEUE queue number to bind (default 0).
    #[serde(default)]
    pub queue_num: u16,
    /// TCP destination ports to intercept (default [443]).
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Named profiles (sets).
    #[serde(default)]
    pub profiles: Vec<ProfileToml>,
}

/// One named profile/set in TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileToml {
    pub name: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub strategies: Vec<StrategyToml>,
}

/// A strategy entry in TOML (tagged).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StrategyToml {
    Mss { mss: u16 },
    StripSack,
    Ttl { ttl: u8 },
    Noop,
}

impl B4Config {
    /// Load from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("read {}: {e}", path.as_ref().display()))?;
        Self::parse(&raw)
    }

    /// Parse from a TOML string.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let cfg: B4Config =
            toml::from_str(raw).map_err(|e| format!("b4 config parse error: {e}"))?;
        // MSS rewrite is only meaningful below the typical 1460-byte MSS; a
        // larger value would be silently applied and do nothing.
        for profile in &cfg.profiles {
            for strat in &profile.strategies {
                if let StrategyToml::Mss { mss } = strat {
                    if *mss < 100 || *mss >= 1460 {
                        return Err(format!(
                            "b4 config: profile '{}': mss must be in [100, 1460), got {mss}",
                            profile.name
                        ));
                    }
                }
            }
        }
        Ok(cfg)
    }

    /// Convert into the engine configuration.
    pub fn into_engine(self) -> EngineConfig {
        let profiles = self
            .profiles
            .into_iter()
            .map(|p| Profile {
                name: p.name,
                domains: p.domains,
                strategies: p.strategies.into_iter().map(|s| s.into()).collect(),
            })
            .collect();
        EngineConfig { profiles }
    }

    /// Default ports.
    pub fn ports(&self) -> Vec<u16> {
        if self.ports.is_empty() {
            vec![443]
        } else {
            self.ports.clone()
        }
    }
}

impl From<StrategyToml> for Strategy {
    fn from(s: StrategyToml) -> Self {
        match s {
            StrategyToml::Mss { mss } => Strategy::Mss { mss },
            StrategyToml::StripSack => Strategy::StripSack,
            StrategyToml::Ttl { ttl } => Strategy::Ttl { ttl },
            StrategyToml::Noop => Strategy::Noop,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profiles() {
        let raw = r#"
queue_num = 0
ports = [443, 8443]

[[profiles]]
name = "youtube"
domains = ["youtube.com", "googlevideo.com"]
strategies = [
  { kind = "mss", mss = 1200 },
  { kind = "strip_sack" },
]

[[profiles]]
name = "chatgpt"
domains = ["openai.com"]
strategies = [
  { kind = "ttl", ttl = 63 },
]
"#;
        let cfg = B4Config::parse(raw).unwrap();
        assert_eq!(cfg.profiles.len(), 2);
        assert_eq!(cfg.ports(), vec![443, 8443]);
        let engine = cfg.into_engine();
        let yt = engine.profile_for("www.youtube.com").unwrap();
        assert_eq!(yt.name, "youtube");
        assert_eq!(yt.strategies.len(), 2);
        let gpt = engine.profile_for("chat.openai.com").unwrap();
        assert_eq!(gpt.name, "chatgpt");
        assert!(engine.profile_for("example.org").is_none());
    }

    #[test]
    fn defaults_when_empty() {
        let cfg = B4Config::default();
        assert_eq!(cfg.ports(), vec![443]);
        assert!(cfg.profiles.is_empty());
    }
}
