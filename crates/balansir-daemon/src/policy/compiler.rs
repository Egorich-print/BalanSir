//! Policy compiler (P5): turns a semantic `DesiredRule` into the
//! backend-neutral wire request the executor installs.
//!
//! Ownership of representations (P4.6 principle):
//!
//! ```text
//! DesiredRule      semantic policy (id, action, flow criteria, domain)
//!    │  PolicyCompiler::compile   (this module, daemon)
//!    ▼
//! ActionRequest    backend-neutral wire request (IpAddr, ports, protocol)
//!    │  executor: to_nft_spec/to_mark_spec  (balansir-executor)
//!    ▼
//! NftRuleSpec      mechanism-specific representation (nft matchers)
//! ```
//!
//! Policy never learns how nftables works; the executor never sees a domain
//! or a semantic flow field. This module is the single place that maps the
//! policy semantics onto the wire contract, so it is unit-testable in
//! isolation.

use balansir_common::{ActionRequest, DesiredRule};
use smallvec::SmallVec;
use std::net::{IpAddr, Ipv4Addr};

/// Compiles a semantic desired rule into an executor-ready `ActionRequest`.
#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyCompiler;

impl PolicyCompiler {
    /// Compile a `DesiredRule` into an `ActionRequest`.
    ///
    /// Flow criteria become concrete request fields: an absent `src_ip`/`dst_ip`
    /// compiles to the unspecified address (no matcher), an absent port to `0`
    /// (no matcher), an absent protocol to `0` (any). The executor treats these
    /// exactly as "no matcher". `trace.policy_id` carries the rule id so the
    /// executor can tag and resolve the installed rule (M3.7).
    pub fn compile(rule: &DesiredRule) -> ActionRequest {
        ActionRequest {
            action: rule.action,
            src_ip: rule
                .flow
                .as_ref()
                .and_then(|f| f.src_ip)
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            dst_ip: rule
                .flow
                .as_ref()
                .and_then(|f| f.dst_ip)
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            src_port: rule.flow.as_ref().and_then(|f| f.src_port).unwrap_or(0),
            dst_port: rule.flow.as_ref().and_then(|f| f.dst_port).unwrap_or(0),
            protocol: rule.flow.as_ref().and_then(|f| f.protocol).unwrap_or(0),
            interface: 0,
            trace: balansir_common::DecisionTrace {
                policy_id: rule.id,
                steps: SmallVec::new(),
                action: rule.action,
                execution_time_us: 0,
                correlation_id: 0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::{Action, FlowCriteria};

    #[test]
    fn no_flow_compiles_to_no_matcher() {
        let rule = DesiredRule {
            id: 7,
            action: Action::Block,
            priority: 100,
            flow: None,
        };
        let req = PolicyCompiler::compile(&rule);
        assert_eq!(req.action, Action::Block);
        assert_eq!(req.src_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(req.dst_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(req.src_port, 0);
        assert_eq!(req.dst_port, 0);
        assert_eq!(req.protocol, 0);
        assert_eq!(req.trace.policy_id, 7);
    }

    #[test]
    fn flow_criteria_compile_to_concrete_fields() {
        let rule = DesiredRule {
            id: 9,
            action: Action::Allow,
            priority: 10,
            flow: Some(FlowCriteria {
                src_ip: Some("192.168.1.10".parse().unwrap()),
                dst_ip: Some("203.0.113.5".parse().unwrap()),
                src_port: Some(40000),
                dst_port: Some(443),
                protocol: Some(6),
                dst_domain: None,
            }),
        };
        let req = PolicyCompiler::compile(&rule);
        assert_eq!(req.src_ip, "192.168.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(req.dst_ip, "203.0.113.5".parse::<IpAddr>().unwrap());
        assert_eq!(req.src_port, 40000);
        assert_eq!(req.dst_port, 443);
        assert_eq!(req.protocol, 6);
        assert_eq!(req.trace.policy_id, 9);
    }

    /// A partially-specified flow keeps only the present fields as matchers;
    /// absent ones fall back to "no matcher" independently.
    #[test]
    fn partial_flow_leaves_absent_fields_as_no_matcher() {
        let rule = DesiredRule {
            id: 1,
            action: Action::Reject,
            priority: 1,
            flow: Some(FlowCriteria {
                dst_port: Some(443),
                ..Default::default()
            }),
        };
        let req = PolicyCompiler::compile(&rule);
        assert_eq!(req.dst_port, 443);
        assert_eq!(req.src_port, 0);
        assert_eq!(req.src_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(req.dst_ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(req.protocol, 0);
    }
}
