use balansir_common::error::{Error, Result};
use std::fmt;
use std::process::Command;
use tracing::{debug, info};

/// Absolute path to the `nft` binary, resolved from standard locations.
fn nft_bin() -> Result<std::path::PathBuf> {
    balansir_common::paths::resolve_bin("nft")
        .ok_or_else(|| Error::Misconfiguration("nft binary not found".into()))
}

#[derive(Debug)]
pub struct NftablesBackend {
    table_name: String,
    chain_name: String,
}

/// Parse `# handle N` from a line of `nft -a list chain` output for the rule
/// whose comment matches `comment`. Returns `None` when absent.
fn parse_handle_for_comment(line: &str, comment: &str) -> Option<String> {
    let quoted = format!("\"{comment}\"");
    if !line.contains(&quoted) {
        return None;
    }
    if let Some(idx) = line.rfind("# handle ") {
        let handle = line[idx + "# handle ".len()..].trim();
        if !handle.is_empty() && handle.chars().all(|c| c.is_ascii_digit()) {
            return Some(handle.to_string());
        }
    }
    None
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

    /// Create the table and chain once, tolerating "already exists" (the
    /// object is present from a previous run) but failing loudly on any other
    /// error — a missing mechanism must not be a silent no-op.
    pub fn init(&self) -> Result<()> {
        self.create_if_absent(["add", "table", "inet", &self.table_name], "table")?;
        self.create_if_absent(
            ["add", "chain", "inet", &self.table_name, &self.chain_name],
            "chain",
        )?;
        Ok(())
    }

    fn create_if_absent<const N: usize>(&self, args: [&str; N], what: &str) -> Result<()> {
        let output = Command::new(nft_bin()?).args(args).output()?;
        if output.status.success() {
            debug!("Created nftables {what}");
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        // nft reports "File exists" (table/chain already present) as an error
        // status; that is the idempotent-until-now case and not a failure.
        if stderr.contains("File exists") {
            debug!("nftables {what} already exists");
            Ok(())
        } else {
            Err(balansir_common::Error::Fatal(format!(
                "nft create {what} failed: {stderr}"
            )))
        }
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

    /// Remove the rule whose comment is exactly `comment` by resolving its
    /// nft handle (`nft -a list chain` shows `# handle N`) and deleting it.
    ///
    /// Handle-based removal is deterministic and does not depend on fragile
    /// flush-all semantics. The comment is matched exactly (quoted form), so
    /// an attacker-controlled rule id cannot match an unrelated rule.
    pub fn remove_rule_by_comment(&self, comment: &str) -> Result<()> {
        let handle = self.find_handle_by_comment(comment)?;
        let Some(handle) = handle else {
            // Already absent — idempotent removal.
            debug!(
                "nft rule comment {:?} not present, nothing to remove",
                comment
            );
            return Ok(());
        };

        let output = Command::new(nft_bin()?)
            .args([
                "delete",
                "rule",
                "inet",
                &self.table_name,
                &self.chain_name,
                "handle",
                &handle,
            ])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(balansir_common::Error::Fatal(format!(
                "nft delete rule failed: {}",
                stderr
            )));
        }
        info!(comment, handle, "Removed nftables rule by handle");
        Ok(())
    }

    /// Return the handle (`# handle N`) of the rule tagged with `comment`, or
    /// `None` if absent. Parses `nft -a list chain`.
    pub fn find_handle_by_comment(&self, comment: &str) -> Result<Option<String>> {
        let output = Command::new(nft_bin()?)
            .args([
                "-a",
                "list",
                "chain",
                "inet",
                &self.table_name,
                &self.chain_name,
            ])
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(balansir_common::Error::Fatal(format!(
                "nft list failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(handle) = parse_handle_for_comment(line, comment) {
                return Ok(Some(handle));
            }
        }
        Ok(None)
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

    /// Report the ids of rules present in the chain, parsed from `balansir:<id>`
    /// comments (A2 inventory — non-authoritative). Includes mark-only rules.
    pub fn list_rule_ids(&self) -> Result<Vec<u32>> {
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
        let mut ids = Vec::new();
        for line in stdout.lines() {
            if let Some(start) = line.find("balansir:") {
                let rest = &line[start + "balansir:".len()..];
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if !digits.is_empty() {
                    if let Ok(id) = digits.parse::<u32>() {
                        ids.push(id);
                    }
                }
            }
        }
        Ok(ids)
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
    Reject,
}

impl fmt::Display for NftVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NftVerdict::Accept => "accept",
            NftVerdict::Drop => "drop",
            NftVerdict::Reject => "reject",
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
    /// Source CIDR, e.g. `10.0.0.0/8` (A3: per-flow matcher).
    pub src_cidr: Option<String>,
    /// Destination CIDR, e.g. `203.0.113.5/32` (A3).
    pub dst_cidr: Option<String>,
    /// Source port (A3).
    pub sport: Option<u16>,
    /// Destination port.
    pub dport: Option<u16>,
    pub verdict: NftVerdict,
    /// Firewall mark set by `meta mark set N` when the rule matches.
    pub mark: Option<u32>,
    /// Stable comment tagging this rule with its rule id, so it can be found
    /// by handle for removal (e.g. `balansir:<id>`).
    pub comment: Option<String>,
}

impl NftRuleSpec {
    pub fn new(verdict: NftVerdict) -> Self {
        Self {
            proto: None,
            src_cidr: None,
            dst_cidr: None,
            sport: None,
            dport: None,
            verdict,
            mark: None,
            comment: None,
        }
    }

    /// Push an address matcher (`ip|ip6 saddr|daddr <cidr>`) into `args`.
    /// IPv6 CIDRs contain ':', so the nft family keyword is derivable from the
    /// CIDR string itself (A4).
    fn push_addr_matcher(args: &mut Vec<String>, keyword: &str, cidr: &str) {
        let family = if cidr.contains(':') { "ip6" } else { "ip" };
        args.push(family.to_string());
        args.push(keyword.to_string());
        args.push(cidr.to_string());
    }

    /// Render the rule into nft arguments (without the base add-rule prefix).
    pub fn render(&self) -> Vec<String> {
        let mut args = Vec::with_capacity(12);
        if let Some(proto) = self.proto {
            args.push("meta".to_string());
            args.push("l4proto".to_string());
            args.push(proto.to_string());
        }
        if let Some(cidr) = &self.src_cidr {
            Self::push_addr_matcher(&mut args, "saddr", cidr);
        }
        if let Some(cidr) = &self.dst_cidr {
            Self::push_addr_matcher(&mut args, "daddr", cidr);
        }
        if let Some(port) = self.sport {
            args.push("th".to_string());
            args.push("sport".to_string());
            args.push(port.to_string());
        }
        if let Some(port) = self.dport {
            args.push("th".to_string());
            args.push("dport".to_string());
            args.push(port.to_string());
        }
        if let Some(mark) = self.mark {
            args.push("meta".to_string());
            args.push("mark".to_string());
            args.push("set".to_string());
            args.push(format!("{mark}"));
        }
        args.push(self.verdict.to_string());
        if let Some(comment) = &self.comment {
            args.push("comment".to_string());
            args.push(format!("\"{comment}\""));
        }
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
            dst_cidr: None,
            sport: None,
            dport: Some(443),
            verdict: NftVerdict::Accept,
            mark: None,
            comment: None,
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
            dst_cidr: None,
            sport: None,
            verdict: NftVerdict::Drop,
            proto: None,
            dport: None,
            mark: None,
            comment: None,
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
            dst_cidr: None,
            sport: None,
            dport: Some(53),
            verdict: NftVerdict::Accept,
            mark: None,
            comment: None,
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

    /// M3.7: fwmark (`meta mark set N`) and comment tagging render correctly.
    #[test]
    fn test_rule_spec_renders_mark_and_comment() {
        let spec = NftRuleSpec {
            proto: Some(NftProto::Tcp),
            src_cidr: None,
            dst_cidr: None,
            sport: None,
            dport: Some(443),
            verdict: NftVerdict::Drop,
            mark: Some(0x10),
            comment: Some("balansir:7".to_string()),
        };
        assert_eq!(
            spec.render(),
            vec![
                "meta".to_string(),
                "l4proto".to_string(),
                "tcp".to_string(),
                "th".to_string(),
                "dport".to_string(),
                "443".to_string(),
                "meta".to_string(),
                "mark".to_string(),
                "set".to_string(),
                "16".to_string(),
                "drop".to_string(),
                "comment".to_string(),
                "\"balansir:7\"".to_string(),
            ]
        );
    }

    #[test]
    fn test_reject_verdict_renders() {
        assert_eq!(NftVerdict::Reject.to_string(), "reject");
    }

    /// M3.7: handle extraction from `nft -a list chain` output is exact and
    /// only matches the tagged comment.
    #[test]
    fn test_parse_handle_for_comment() {
        let line = "\t\tmeta l4proto tcp th dport 443 drop comment \"balansir:7\" # handle 9\n";
        assert_eq!(
            parse_handle_for_comment(line, "balansir:7"),
            Some("9".to_string())
        );
        // A different comment does not match this line.
        assert_eq!(parse_handle_for_comment(line, "balansir:8"), None);
        // Non-numeric trailing garbage is not a handle.
        let bad = "\t\t... comment \"balansir:1\" # handle notanumber\n";
        assert_eq!(parse_handle_for_comment(bad, "balansir:1"), None);
    }

    /// A3 (ADR-018): a full flow rule — src, dst, sport, dport, proto —
    /// renders family-aware (`ip`/`ip6` by the address in each CIDR).
    #[test]
    fn test_flow_rule_render_v4_and_v6() {
        // IPv4 flow: src + dst + ports + proto.
        let v4 = NftRuleSpec {
            proto: Some(NftProto::Tcp),
            src_cidr: Some("10.0.0.0/8".to_string()),
            dst_cidr: Some("203.0.113.5/32".to_string()),
            sport: Some(40000),
            dport: Some(443),
            verdict: NftVerdict::Drop,
            mark: None,
            comment: None,
        };
        assert_eq!(
            v4.render(),
            vec![
                "meta",
                "l4proto",
                "tcp",
                "ip",
                "saddr",
                "10.0.0.0/8",
                "ip",
                "daddr",
                "203.0.113.5/32",
                "th",
                "sport",
                "40000",
                "th",
                "dport",
                "443",
                "drop",
            ]
        );

        // IPv6 flow: both addresses are v6 -> both use the `ip6` keyword.
        let v6 = NftRuleSpec {
            proto: Some(NftProto::Udp),
            src_cidr: Some("2001:db8::/64".to_string()),
            dst_cidr: Some("2001:db8::5/128".to_string()),
            sport: None,
            dport: Some(53),
            verdict: NftVerdict::Accept,
            mark: None,
            comment: None,
        };
        assert_eq!(
            v6.render(),
            vec![
                "meta",
                "l4proto",
                "udp",
                "ip6",
                "saddr",
                "2001:db8::/64",
                "ip6",
                "daddr",
                "2001:db8::5/128",
                "th",
                "dport",
                "53",
                "accept",
            ]
        );
    }
}
