//! DPI-bypass configuration (profiles/sets).
//!
//! Authored as TOML in the style of b4 "sets": named profiles each with a
//! list of domains and the strategies applied to their traffic.
//!
//! Two strategy shapes are supported:
//! - **Legacy**: a list of `StrategyToml` entries (`{ kind = "mss", mss = ... }`
//!   etc.);
//! - **Full mission set** (`B4Set`): the classic b4 tcp/udp/fragmentation/
//!   faking/targets JSON. A profile may embed a full set under `[profiles.set]`
//!   or the whole config may be an array of sets.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::set::B4Set;
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
    /// UDP destination ports to intercept for UDP faking (default [443]).
    #[serde(default)]
    pub udp_ports: Vec<u16>,
    /// Named profiles (sets).
    #[serde(default)]
    pub profiles: Vec<ProfileToml>,
    /// Full strategy sets (mission §6 format). When present, these drive the
    /// engine in addition to (or instead of) the legacy profiles.
    #[serde(default)]
    pub sets: Vec<B4Set>,
}

/// One named profile/set in TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileToml {
    pub name: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub strategies: Vec<StrategyToml>,
    /// Optional embedded full strategy set (mission §6).
    #[serde(default)]
    pub set: Option<B4Set>,
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

    /// Convert into the engine configuration (legacy profiles only).
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

    /// Default UDP ports to intercept for UDP faking.
    pub fn udp_ports(&self) -> Vec<u16> {
        if self.udp_ports.is_empty() {
            vec![443]
        } else {
            self.udp_ports.clone()
        }
    }

    /// All full strategy sets (embedded in profiles + top-level `sets`).
    pub fn all_sets(&self) -> Vec<B4Set> {
        let mut all = self.sets.clone();
        for p in &self.profiles {
            if let Some(set) = &p.set {
                all.push(set.clone());
            }
        }
        all
    }

    /// Whether any set wants UDP interception.
    pub fn wants_udp(&self) -> bool {
        self.all_sets().iter().any(|s| s.wants_udp())
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
        assert_eq!(cfg.udp_ports(), vec![443]);
        assert!(cfg.profiles.is_empty());
        assert!(cfg.all_sets().is_empty());
        assert!(!cfg.wants_udp());
    }

    #[test]
    fn parses_full_mission_sets_from_toml() {
        // The shipped config/dpi.toml shape: [[sets]] + nested [sets.tcp] etc.
        let raw = r#"
queue_num = 0
ports = [443]
udp_ports = [443]

[[sets]]
name = "youtube"
enabled = true

[sets.tcp]
conn_bytes_limit = 19
seg2delay = 20
seg2delay_max = 60
syn_ttl = 7
drop_sack = false

[sets.tcp.incoming]
mode = "off"
min = 14
max = 14
fake_ttl = 7
fake_count = 3
strategy = "badsum"

[sets.tcp.desync]
mode = "off"
ttl = 7
count = 3
post_desync = false

[sets.tcp.win]
mode = "off"
values = [0, 1460, 8192, 65535]

[sets.tcp.duplicate]
enabled = false
count = 3

[sets.udp]
mode = "fake"
fake_seq_length = 6
fake_len = 64
faking_strategy = "none"
dport_filter = ""
filter_quic = "parse"
filter_stun = true
conn_bytes_limit = 8
seg2delay = 10
seg2delay_max = 40

[sets.fragmentation]
strategy = "combo"
reverse_order = true
tlsrec_pos = 0
middle_sni = true
sni_position = 1
oob_position = 0
oob_char = 120
seq_overlap_pattern = []

[sets.fragmentation.combo]
first_byte_split = true
extension_split = true
shuffle_mode = "full"
first_delay_ms = 30
jitter_max_us = 1000
decoy_enabled = false
decoy_snis = ["ya.ru","vk.com","mail.ru","dzen.ru"]

[sets.fragmentation.disorder]
shuffle_mode = "full"
min_jitter_us = 1000
max_jitter_us = 3000

[sets.faking]
sni = true
ttl = 8
strategy = "pastseq"
seq_offset = 10000
sni_seq_length = 1
sni_type = 3
custom_payload = ""
payload_file = ""
tls_mod = []
timestamp_decrease = 600000

[sets.faking.sni_mutation]
mode = "off"
grease_count = 3
padding_size = 2048
fake_ext_count = 5
fake_snis = []

[sets.targets]
sni_domains = []
ip = []
geosite_categories = ["youtube"]
geoip_categories = []

[sets.dns]
enabled = false
target_dns = ""
fragment_query = false
"#;
        let cfg = B4Config::parse(raw).unwrap();
        let sets = cfg.all_sets();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].name, "youtube");
        assert!(sets[0].enabled);
        assert!(sets[0].wants_udp());
        assert!(cfg.wants_udp());
        assert_eq!(sets[0].targets.geosite_categories, vec!["youtube"]);
        assert_eq!(sets[0].fragmentation.combo.decoy_snis.len(), 4);
        assert_eq!(sets[0].faking.seq_offset, 10000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn set_matching_uses_geosite() {
        let raw = r#"
[[sets]]
name = "youtube"
enabled = true
[sets.targets]
geosite_categories = ["youtube"]
"#;
        let cfg = B4Config::parse(raw).unwrap();
        let sets = cfg.all_sets();
        let set = &sets[0];
        // The engine's set_matches_host uses the geosite store; the store
        // matches subdomains of youtube.com.
        assert!(crate::engine::set_matches_host(set, "www.youtube.com"));
        assert!(crate::engine::set_matches_host(set, "i.ytimg.com"));
        assert!(!crate::engine::set_matches_host(set, "example.com"));
    }
}
