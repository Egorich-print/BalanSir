use balansir_common::error::{Error, Result};
use std::fmt;
use std::process::Command;
use tracing::{debug, info};

/// Absolute path to the `nft` binary, resolved from standard locations.
fn nft_bin() -> Result<std::path::PathBuf> {
    balansir_common::paths::resolve_bin("nft")
        .ok_or_else(|| Error::Misconfiguration("nft binary not found".into()))
}

pub struct NftablesBackend {
    table_name: String,
    chain_name: String,
}

/// Valid identifier per nftables grammar: `[A-Za-z0-9_-]+`.
fn validate_identifier(name: &str) -> Result<()> {
    if !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Ok(())
    } else {
        Err(Error::Misconfiguration(format!(
            "invalid nftables identifier: {:?}",
            name
        )))
    }
}

impl NftablesBackend {
    pub fn new(table_name: &str, chain_name: &str) -> Result<Self> {
        validate_identifier(table_name)?;
        validate_identifier(chain_name)?;
        Ok(Self {
            table_name: table_name.to_string(),
            chain_name: chain_name.to_string(),
        })
    }

    /// Render a single rule command targeting this table/chain.
    fn rule_args(&self, spec: &NftRuleSpec) -> Vec<String> {
        let mut args = vec![
            "add".to_string(),
            "rule".to_string(),
            "inet".to_string(),
            self.table_name.clone(),
            self.chain_name.clone(),
        ];
        args.extend(spec.render());
        args
    }

    pub fn init(&self) -> Result<()> {
        // Create table if not exists
        let output = Command::new(nft_bin()?)
            .args(["add", "table", "inet", &self.table_name])
            .output();

        match output {
            Ok(_) => {
                debug!("Created nftables table: {}", self.table_name);
            }
            Err(e) => {
                // Table might already exist
                debug!("Table creation result: {}", e);
            }
        }

        // Create chain if not exists
        let output = Command::new(nft_bin()?)
            .args(["add", "chain", "inet", &self.table_name, &self.chain_name])
            .output();

        match output {
            Ok(_) => {
                debug!("Created nftables chain: {}", self.chain_name);
            }
            Err(e) => {
                debug!("Chain creation result: {}", e);
            }
        }

        Ok(())
    }

    pub fn add_rule(&self, spec: &NftRuleSpec) -> Result<()> {
        let output = Command::new(nft_bin()?)
            .args(self.rule_args(spec))
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(balansir_common::Error::Fatal(format!(
                "nft add rule failed: {}",
                stderr
            )));
        }

        debug!("Added nftables rule: {}", spec);
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        let output = Command::new(nft_bin()?)
            .args(["flush", "chain", "inet", &self.table_name, &self.chain_name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(balansir_common::Error::Fatal(format!(
                "nft flush failed: {}",
                stderr
            )));
        }

        info!("Flushed nftables chain: {}", self.chain_name);
        Ok(())
    }

    pub fn list_rules(&self) -> Result<Vec<String>> {
        let output = Command::new(nft_bin()?)
            .args(["list", "chain", "inet", &self.table_name, &self.chain_name])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(balansir_common::Error::Fatal(format!(
                "nft list failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let rules: Vec<String> = stdout
            .lines()
            .filter(|line| line.contains("accept") || line.contains("drop"))
            .map(|line| line.trim().to_string())
            .collect();

        Ok(rules)
    }

    #[cfg(test)]
    fn render_args(&self, spec: &NftRuleSpec) -> Vec<String> {
        self.rule_args(spec)
    }
}

/// L4 protocol selector for a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftProto {
    Tcp,
    Udp,
}

impl fmt::Display for NftProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NftProto::Tcp => "tcp",
            NftProto::Udp => "udp",
        })
    }
}

/// Verdict applied when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftVerdict {
    Accept,
    Drop,
}

impl fmt::Display for NftVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NftVerdict::Accept => "accept",
            NftVerdict::Drop => "drop",
        })
    }
}

/// A single structured netfilter rule.
///
/// Rendered as positional arguments to `nft add rule`, so no free-form
/// strings are ever interpolated into a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftRuleSpec {
    pub proto: Option<NftProto>,
    /// Source CIDR, e.g. `10.0.0.0/8`.
    pub src_cidr: Option<String>,
    /// Destination port.
    pub dport: Option<u16>,
    pub verdict: NftVerdict,
}

impl NftRuleSpec {
    pub fn new(verdict: NftVerdict) -> Self {
        Self {
            proto: None,
            src_cidr: None,
            dport: None,
            verdict,
        }
    }

    /// Render the rule into nft arguments (without the base add-rule prefix).
    pub fn render(&self) -> Vec<String> {
        let mut args = Vec::with_capacity(6);
        if let Some(proto) = self.proto {
            args.push("meta".to_string());
            args.push("l4proto".to_string());
            args.push(proto.to_string());
        }
        if let Some(cidr) = &self.src_cidr {
            args.push("ip".to_string());
            args.push("saddr".to_string());
            args.push(cidr.clone());
        }
        if let Some(port) = self.dport {
            args.push("th".to_string());
            args.push("dport".to_string());
            args.push(port.to_string());
        }
        args.push(self.verdict.to_string());
        args
    }
}

impl fmt::Display for NftRuleSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let line = self.render().join(" ");
        write!(f, "{}", line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_creation() {
        let backend = NftablesBackend::new("balansir", "forward").unwrap();
        assert_eq!(backend.table_name, "balansir");
        assert_eq!(backend.chain_name, "forward");
    }

    #[test]
    fn test_identifier_validation() {
        assert!(NftablesBackend::new("balansir", "forward").is_ok());
        assert!(NftablesBackend::new("ok-bad_1", "forward").is_ok());
        assert!(NftablesBackend::new("", "forward").is_err());
        assert!(NftablesBackend::new("bad name", "forward").is_err());
        assert!(NftablesBackend::new("bad@name", "forward").is_err());
        assert!(NftablesBackend::new("bad/name", "forward").is_err());
        assert!(NftablesBackend::new(&"x".repeat(65), "forward").is_err());
    }

    #[test]
    fn test_rule_spec_render_drop_all() {
        let spec = NftRuleSpec::new(NftVerdict::Drop);
        assert_eq!(spec.render(), vec!["drop"]);
    }

    #[test]
    fn test_rule_spec_render_full() {
        let spec = NftRuleSpec {
            proto: Some(NftProto::Tcp),
            src_cidr: Some("10.0.0.0/8".to_string()),
            dport: Some(443),
            verdict: NftVerdict::Accept,
        };
        assert_eq!(
            spec.render(),
            vec![
                "meta".to_string(),
                "l4proto".to_string(),
                "tcp".to_string(),
                "ip".to_string(),
                "saddr".to_string(),
                "10.0.0.0/8".to_string(),
                "th".to_string(),
                "dport".to_string(),
                "443".to_string(),
                "accept".to_string(),
            ]
        );
    }

    #[test]
    fn test_rule_spec_render_src_only() {
        let spec = NftRuleSpec {
            src_cidr: Some("192.168.1.0/24".to_string()),
            verdict: NftVerdict::Drop,
            proto: None,
            dport: None,
        };
        assert_eq!(
            spec.render(),
            vec![
                "ip".to_string(),
                "saddr".to_string(),
                "192.168.1.0/24".to_string(),
                "drop".to_string(),
            ]
        );
    }

    #[test]
    fn test_rule_args_prefix() {
        let backend = NftablesBackend::new("balansir", "forward").unwrap();
        let spec = NftRuleSpec {
            proto: Some(NftProto::Udp),
            src_cidr: None,
            dport: Some(53),
            verdict: NftVerdict::Accept,
        };
        assert_eq!(
            backend.render_args(&spec),
            vec![
                "add".to_string(),
                "rule".to_string(),
                "inet".to_string(),
                "balansir".to_string(),
                "forward".to_string(),
                "meta".to_string(),
                "l4proto".to_string(),
                "udp".to_string(),
                "th".to_string(),
                "dport".to_string(),
                "53".to_string(),
                "accept".to_string(),
            ]
        );
    }
}
