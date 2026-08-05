use balansir_common::{Action, DecisionTrace, MatcherStep};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

pub mod fast_match;
pub mod matcher;
pub mod rules;

pub use fast_match::*;
pub use matcher::*;
pub use rules::*;

/// Policy engine evaluates packet context against rules
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

/// A single policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: u32,
    pub name: String,
    pub priority: u32,
    pub enabled: bool,
    pub matcher: Matcher,
    pub action: Action,
    pub fallback: Option<Action>,
}

impl PolicyEngine {
    /// Create a new policy engine with the given rules
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        let mut sorted_rules = rules;
        sorted_rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
        Self {
            rules: sorted_rules,
        }
    }

    /// Evaluate packet context and return decision trace
    pub fn evaluate(&self, ctx: &PacketContext) -> DecisionTrace {
        let start = std::time::Instant::now();
        let mut steps = SmallVec::new();
        let mut matched_action = Action::Allow;

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let matched = rule.matcher.matches(ctx);
            steps.push(MatcherStep {
                rule_id: rule.id,
                matched,
                reason: 0,
            });

            if matched {
                matched_action = rule.action;
                break;
            }
        }

        let execution_time_us = start.elapsed().as_micros() as u64;

        DecisionTrace {
            policy_id: 0,
            steps,
            action: matched_action,
            execution_time_us,
            correlation_id: 0,
        }
    }

    /// Get all rules
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Add a new rule
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
    }

    /// Remove a rule by ID
    pub fn remove_rule(&mut self, id: u32) {
        self.rules.retain(|r| r.id != id);
    }
}

/// Packet context for policy evaluation
#[derive(Debug, Clone)]
pub struct PacketContext {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub domain_hash: Option<u32>,
    pub interface: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_engine_basic() {
        let rules = vec![
            PolicyRule {
                id: 1,
                name: "block-ad".to_string(),
                priority: 100,
                enabled: true,
                matcher: Matcher::DomainSuffix { suffix: 12345 },
                action: Action::Block,
                fallback: None,
            },
            PolicyRule {
                id: 2,
                name: "allow-rest".to_string(),
                priority: 0,
                enabled: true,
                matcher: Matcher::Any,
                action: Action::Allow,
                fallback: None,
            },
        ];

        let engine = PolicyEngine::new(rules);

        let ctx = PacketContext {
            src_ip: [192, 168, 1, 1],
            dst_ip: [142, 250, 80, 46],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: Some(12345),
            interface: None,
        };

        let trace = engine.evaluate(&ctx);
        assert_eq!(trace.action, Action::Block);
        assert_eq!(trace.steps.len(), 1);
        assert!(trace.steps[0].matched);
    }

    #[test]
    fn test_policy_engine_priority() {
        let rules = vec![
            PolicyRule {
                id: 1,
                name: "low-priority".to_string(),
                priority: 10,
                enabled: true,
                matcher: Matcher::Any,
                action: Action::Allow,
                fallback: None,
            },
            PolicyRule {
                id: 2,
                name: "high-priority".to_string(),
                priority: 100,
                enabled: true,
                matcher: Matcher::Any,
                action: Action::Block,
                fallback: None,
            },
        ];

        let engine = PolicyEngine::new(rules);

        let ctx = PacketContext {
            src_ip: [192, 168, 1, 1],
            dst_ip: [142, 250, 80, 46],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: None,
            interface: None,
        };

        let trace = engine.evaluate(&ctx);
        assert_eq!(trace.action, Action::Block);
    }
}
