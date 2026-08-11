//! B4 policy interface (P7.1, ADR-024).
//!
//! A `B4Profile` declares, per flow, which adaptation mechanisms are allowed
//! and how the flow fails when no secure path exists. This is **policy**: it
//! is authored above B4 and consumed by the engine. B4 never invents policy.

use serde::{Deserialize, Serialize};

/// How a flow behaves when no protected mechanism is available.
///
/// The default is `Strict` (ADR-024): a flow that requires a protected path
/// and has no secure mechanism must fail, never silently downgrade security.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum B4FailSemantic {
    /// Protected path required; no secure mechanism -> fail the connection.
    #[default]
    Strict,
    /// Secure mechanism preferred; temporarily unavailable -> restricted
    /// fallback (only explicitly allowed).
    Safe,
    /// Best available connectivity; direct may be used.
    Default,
}

/// Which adaptation mechanisms a flow may use. Each maps to a capability with
/// an observable result; the menu is deliberately small (P7.1: MTU + DNS-path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B4Capability {
    /// Adjust the effective MTU / MSS of the direct path for this flow.
    Mtu,
    /// Prefer a different DNS path for this flow's domain resolution.
    DnsPath,
}

/// Policy for one flow: allowed capabilities + fail semantic.
///
/// The fallback *ladder* is expressed by the ordered `capabilities` list plus
/// `allow_direct`/`allow_tunnel` — the engine executes within these bounds and
/// never chooses to violate the fail semantic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct B4Profile {
    /// Allowed adaptation mechanisms, in preference order.
    #[serde(default)]
    pub capabilities: Vec<B4Capability>,
    /// Fail semantic for this flow (default Strict).
    #[serde(default)]
    pub fail: B4FailSemantic,
    /// Whether a plain direct path (no adaptation) is acceptable.
    #[serde(default = "default_true")]
    pub allow_direct: bool,
    /// Whether a tunnel (VPN) is an acceptable final fallback for this flow.
    #[serde(default)]
    pub allow_tunnel: bool,
}

impl Default for B4Profile {
    fn default() -> Self {
        Self {
            capabilities: Vec::new(),
            fail: B4FailSemantic::Strict,
            // Direct is always acceptable unless policy says otherwise; only
            // the tunnel fallback and capabilities opt in.
            allow_direct: true,
            allow_tunnel: false,
        }
    }
}

fn default_true() -> bool {
    true
}

/// The daemon-authored policy table mapping a flow key (domain) to its B4
/// profile. This is the *only* place B4 reads intent from.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct B4Policy {
    #[serde(default)]
    pub flows: Vec<B4FlowRule>,
}

/// A single B4 policy entry: match a domain (or a direct-path marker) and
/// attach a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct B4FlowRule {
    /// Domain suffix this rule applies to (e.g. "example.com").
    pub domain: String,
    pub profile: B4Profile,
}

impl B4Policy {
    /// The domains the policy knows about (for pre-seeding the engine).
    pub fn flow_domains(&self) -> Vec<String> {
        self.flows.iter().map(|r| r.domain.clone()).collect()
    }

    /// The profile for a flow, by its domain. Unknown domains get the default
    /// profile (Strict, direct allowed, no capabilities, no tunnel) so the
    /// engine never adapts a flow the policy did not admit to B4.
    pub fn profile_for(&self, domain: &str) -> B4Profile {
        let lower = domain.to_ascii_lowercase();
        self.flows
            .iter()
            .find(|r| {
                lower == r.domain.to_ascii_lowercase()
                    || lower.ends_with(&format!(".{}", r.domain.to_ascii_lowercase()))
            })
            .map(|r| r.profile.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_is_strict_direct_only() {
        let p = B4Profile::default();
        assert_eq!(p.fail, B4FailSemantic::Strict);
        assert!(p.allow_direct);
        assert!(!p.allow_tunnel);
        assert!(p.capabilities.is_empty());
    }

    #[test]
    fn profile_matches_domain_and_subdomains() {
        let policy = B4Policy {
            flows: vec![B4FlowRule {
                domain: "example.com".into(),
                profile: B4Profile {
                    capabilities: vec![B4Capability::Mtu, B4Capability::DnsPath],
                    fail: B4FailSemantic::Safe,
                    allow_direct: true,
                    allow_tunnel: false,
                },
            }],
        };
        assert_eq!(policy.profile_for("example.com").fail, B4FailSemantic::Safe);
        assert_eq!(
            policy.profile_for("video.example.com").capabilities,
            vec![B4Capability::Mtu, B4Capability::DnsPath]
        );
        // Unknown domain -> strict default, no capabilities.
        let unknown = policy.profile_for("other.net");
        assert_eq!(unknown.fail, B4FailSemantic::Strict);
        assert!(unknown.capabilities.is_empty());
    }
}
