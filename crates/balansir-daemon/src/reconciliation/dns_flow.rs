//! DNS/conn metadata → compiled flow rules (A3, ADR-018).
//!
//! The daemon is the sole compilation authority. A `DnsRegistry` provides a
//! non-authoritative view of "domain → resolved IPs" (populated by the DNS
//! forwarder driver or an external feed). A `FlowCompiler` expands a desired
//! rule that carries `flow.dst_domain` into one concrete per-IP `DesiredRule`
//! per resolved address, each with a stable derived id, so the normal planner
//! can diff them like any other flow rule. The executor never receives a rule
//! that still names a domain.

use balansir_common::{DesiredRule, DesiredState};
use std::collections::HashMap;
use std::net::IpAddr;

/// Stable FNV-1a 32-bit hash used to derive a compiled rule's id from the
/// source rule id and the resolved address. Deterministic, so the same
/// domain→IP mapping always yields the same rule id (A1/A2-friendly).
fn derived_rule_id(base: u32, ip: &IpAddr) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in base.to_le_bytes().into_iter().chain(ip.to_string().bytes()) {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// A non-authoritative registry of domain → resolved IP addresses.
///
/// The daemon populates it from its DNS/conn observation source; the compiler
/// reads it but treats missing/unknown domains as "compile to nothing" (the
/// rule is dropped from the compiled desired state until it resolves).
#[derive(Debug, Default, Clone)]
pub struct DnsRegistry {
    inner: std::sync::Arc<std::sync::Mutex<HashMap<String, Vec<IpAddr>>>>,
}

impl DnsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the resolved addresses for a domain (replaces previous set).
    pub fn insert(&self, domain: &str, ips: Vec<IpAddr>) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(domain.to_ascii_lowercase(), ips);
    }

    /// Remove a domain mapping entirely.
    pub fn remove(&self, domain: &str) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&domain.to_ascii_lowercase());
    }

    /// Resolved addresses for a domain, or `None` if unknown.
    pub fn resolve(&self, domain: &str) -> Option<Vec<IpAddr>> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&domain.to_ascii_lowercase())
            .cloned()
    }
}

/// Compiles domain-based desired rules into concrete per-IP flow rules.
#[derive(Debug, Clone)]
pub struct FlowCompiler {
    registry: DnsRegistry,
}

impl FlowCompiler {
    pub fn new(registry: DnsRegistry) -> Self {
        Self { registry }
    }

    /// Expand a single desired rule. A rule with `flow.dst_domain` becomes one
    /// rule per resolved IP (derived id, concrete `dst_ip`, domain cleared). A
    /// rule without a domain passes through unchanged. An unresolved domain
    /// compiles to nothing (not enforced until it resolves).
    pub fn compile_rule(&self, rule: &DesiredRule) -> Vec<DesiredRule> {
        let Some(flow) = &rule.flow else {
            return vec![rule.clone()];
        };
        let Some(domain) = &flow.dst_domain else {
            return vec![rule.clone()];
        };

        let Some(ips) = self.registry.resolve(domain) else {
            tracing::warn!(
                domain,
                "domain has no resolved addresses; rule {} not enforced",
                rule.id
            );
            return Vec::new();
        };

        ips.into_iter()
            .map(|ip| {
                let mut compiled = flow.clone();
                compiled.dst_ip = Some(ip);
                compiled.dst_domain = None;
                DesiredRule {
                    id: derived_rule_id(rule.id, &ip),
                    action: rule.action,
                    priority: rule.priority,
                    flow: Some(compiled),
                }
            })
            .collect()
    }

    /// Compile a full desired state.
    pub fn compile(&self, state: &DesiredState) -> DesiredState {
        let mut rules = Vec::new();
        for rule in &state.rules {
            rules.extend(self.compile_rule(rule));
        }
        DesiredState {
            rules,
            drivers: state.drivers.clone(),
            qos: state.qos.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::{Action, FlowCriteria};

    fn rule(id: u32, domain: Option<&str>) -> DesiredRule {
        DesiredRule {
            id,
            action: Action::Block,
            priority: 100,
            flow: domain.map(|d| FlowCriteria {
                dst_domain: Some(d.to_string()),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn domain_rule_compiles_to_one_rule_per_ip() {
        let registry = DnsRegistry::new();
        registry.insert(
            "api.example.com",
            vec![
                "203.0.113.5".parse().unwrap(),
                "203.0.113.6".parse().unwrap(),
            ],
        );
        let compiler = FlowCompiler::new(registry);

        let out = compiler.compile_rule(&rule(7, Some("api.example.com")));
        assert_eq!(out.len(), 2);
        let ips: Vec<String> = out
            .iter()
            .map(|r| r.flow.as_ref().unwrap().dst_ip.unwrap().to_string())
            .collect();
        assert!(ips.contains(&"203.0.113.5".to_string()));
        assert!(ips.contains(&"203.0.113.6".to_string()));
        // Derived ids are stable and distinct, and no rule still carries the
        // domain (the executor must never see a domain).
        assert!(out[0].id != 7 && out[1].id != 7 && out[0].id != out[1].id);
        assert!(out
            .iter()
            .all(|r| r.flow.as_ref().unwrap().dst_domain.is_none()));
    }

    #[test]
    fn domain_rule_is_deterministic() {
        let registry = DnsRegistry::new();
        registry.insert("x.example.com", vec!["192.0.2.1".parse().unwrap()]);
        let compiler = FlowCompiler::new(registry);
        let a = compiler.compile_rule(&rule(3, Some("x.example.com")));
        let b = compiler.compile_rule(&rule(3, Some("x.example.com")));
        assert_eq!(a, b);
    }

    #[test]
    fn no_domain_rule_passes_through() {
        let compiler = FlowCompiler::new(DnsRegistry::new());
        let plain = rule(5, None);
        assert_eq!(compiler.compile_rule(&plain), vec![plain.clone()]);
        // And an unresolved domain compiles to nothing (not enforced).
        assert!(compiler
            .compile_rule(&rule(6, Some("missing.example.com")))
            .is_empty());
    }
}
