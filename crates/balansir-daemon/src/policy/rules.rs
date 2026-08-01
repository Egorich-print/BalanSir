use serde::{Deserialize, Serialize};

use super::matcher::Matcher;
use balansir_common::Action;

/// Policy file structure loaded from TOML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFile {
    pub rules: Vec<PolicyRuleToml>,
}

/// Single policy rule in TOML format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleToml {
    pub name: String,
    pub priority: u32,
    pub enabled: bool,
    pub matcher: MatcherToml,
    pub action: ActionToml,
}

/// Matcher types for TOML configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MatcherToml {
    Any,
    None,
    DomainSuffix { suffix: String },
    DomainExact { domain: String },
    IpRange { cidr: String },
    Port { port: u16 },
    PortRange { start: u16, end: u16 },
    Protocol { proto: u8 },
}

/// Action types for TOML configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ActionToml {
    Route { table: u32 },
    Forward { driver: String },
    Block,
    Reject,
    Allow,
}

fn hash_domain(domain: &str) -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    domain.hash(&mut hasher);
    hasher.finish() as u32
}

fn parse_cidr(cidr: &str) -> Result<([u8; 4], u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR format: {}", cidr));
    }

    let ip_parts: Vec<u8> = parts[0]
        .split('.')
        .map(|s| s.parse::<u8>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Invalid IP address: {}", e))?;

    if ip_parts.len() != 4 {
        return Err(format!("Invalid IP address: {}", parts[0]));
    }

    let mask: u8 = parts[1]
        .parse()
        .map_err(|e| format!("Invalid prefix length: {}", e))?;

    if mask > 32 {
        return Err(format!("Prefix length must be <= 32: {}", mask));
    }

    Ok(([ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]], mask))
}

impl PolicyRuleToml {
    /// Convert TOML rule to internal representation
    pub fn to_rule(&self, id: u32) -> Result<super::PolicyRule, String> {
        let matcher = match &self.matcher {
            MatcherToml::Any => Matcher::Any,
            MatcherToml::None => Matcher::None,
            MatcherToml::DomainSuffix { suffix } => Matcher::DomainSuffix {
                suffix: hash_domain(suffix),
            },
            MatcherToml::DomainExact { domain } => Matcher::DomainExact {
                hash: hash_domain(domain),
            },
            MatcherToml::IpRange { cidr } => {
                let (base, mask) = parse_cidr(cidr)?;
                Matcher::IpRange { base, mask }
            }
            MatcherToml::Port { port } => Matcher::Port { port: *port },
            MatcherToml::PortRange { start, end } => Matcher::PortRange {
                start: *start,
                end: *end,
            },
            MatcherToml::Protocol { proto } => Matcher::Protocol { proto: *proto },
        };

        let action = match &self.action {
            ActionToml::Route { table } => Action::Route { table: *table },
            ActionToml::Forward { driver } => {
                let driver_hash = hash_domain(driver);
                Action::Forward {
                    driver: balansir_common::DriverId(driver_hash),
                }
            }
            ActionToml::Block => Action::Block,
            ActionToml::Reject => Action::Reject,
            ActionToml::Allow => Action::Allow,
        };

        Ok(super::PolicyRule {
            id,
            name: self.name.clone(),
            priority: self.priority,
            enabled: self.enabled,
            matcher,
            action,
            fallback: None,
        })
    }
}

impl PolicyFile {
    /// Load policy file from TOML
    pub fn load(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read policy file: {}", e))?;
        let policy: PolicyFile =
            toml::from_str(&content).map_err(|e| format!("Failed to parse policy file: {}", e))?;
        Ok(policy)
    }

    /// Convert TOML rules to internal representation
    pub fn to_rules(&self) -> Result<Vec<super::PolicyRule>, String> {
        self.rules
            .iter()
            .enumerate()
            .map(|(i, r)| r.to_rule(i as u32 + 1))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_file_parse() {
        let toml = r#"
[[rules]]
name = "youtube-hysteria"
priority = 100
enabled = true

[rules.matcher]
type = "DomainSuffix"
suffix = ".youtube.com"

[rules.action]
type = "Forward"
driver = "hysteria-primary"
"#;

        let policy: PolicyFile = toml::from_str(toml).unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].name, "youtube-hysteria");
    }

    #[test]
    fn test_cidr_parsing() {
        let (ip, mask) = parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ip, [192, 168, 1, 0]);
        assert_eq!(mask, 24);
    }

    #[test]
    fn test_cidr_parsing_invalid() {
        assert!(parse_cidr("invalid").is_err());
        assert!(parse_cidr("192.168.1.0/33").is_err());
        assert!(parse_cidr("999.999.999.999/24").is_err());
    }
}
