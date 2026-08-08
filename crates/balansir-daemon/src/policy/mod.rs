use balansir_common::{Action, DecisionTrace, HealthView, MatcherStep};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

pub mod error;
pub mod fast_match;
pub mod matcher;
pub mod rules;

pub use error::*;
pub use fast_match::*;
pub use matcher::*;
pub use rules::*;

/// Policy engine evaluates packet context against rules
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    default_deny: bool,
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
    /// Create a new policy engine with the given rules (fail-open by default).
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self::with_policy(rules, false)
    }

    /// Create a policy engine with configurable default-deny.
    ///
    /// When `default_deny` is true, unmatched traffic — and `Forward` actions
    /// for unhealthy drivers with no fallback — resolve to `Block` instead of
    /// `Allow`.
    pub fn with_policy(rules: Vec<PolicyRule>, default_deny: bool) -> Self {
        let mut sorted_rules = rules;
        sorted_rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
        Self {
            rules: sorted_rules,
            default_deny,
        }
    }

    fn default_action(&self) -> Action {
        if self.default_deny {
            Action::Block
        } else {
            Action::Allow
        }
    }

    /// Resolve a matched rule's action, applying the health-driven fallback.
    fn resolve_action(&self, rule: &PolicyRule, health: &HealthView) -> Action {
        match rule.action {
            Action::Forward { driver } if !health.is_routable(driver) => match rule.fallback {
                Some(fallback) => fallback,
                None => self.default_action(),
            },
            action => action,
        }
    }

    /// Evaluate packet context (with current driver health) and return trace.
    pub fn evaluate(&self, ctx: &PacketContext, health: &HealthView) -> DecisionTrace {
        let start = std::time::Instant::now();
        let mut steps = SmallVec::new();
        let mut matched_action = self.default_action();

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
                matched_action = self.resolve_action(rule, health);
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

    fn ctx_with_domain(hash: Option<u32>) -> PacketContext {
        PacketContext {
            src_ip: [192, 168, 1, 1],
            dst_ip: [142, 250, 80, 46],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: hash,
            interface: None,
        }
    }

    fn healthy() -> HealthView {
        HealthView::new()
    }

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

        let ctx = ctx_with_domain(Some(12345));

        let trace = engine.evaluate(&ctx, &healthy());
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

        let trace = engine.evaluate(&ctx_with_domain(None), &healthy());
        assert_eq!(trace.action, Action::Block);
    }

    #[test]
    fn test_forward_fallback_when_driver_unhealthy() {
        let rules = vec![PolicyRule {
            id: 1,
            name: "youtube-via-tunnel".to_string(),
            priority: 100,
            enabled: true,
            matcher: Matcher::Any,
            action: Action::Forward {
                driver: balansir_common::DriverId::WireGuard,
            },
            fallback: Some(Action::Allow),
        }];

        let engine = PolicyEngine::new(rules);

        // Healthy driver routes through the tunnel.
        let trace = engine.evaluate(&ctx_with_domain(None), &healthy());
        assert_eq!(
            trace.action,
            Action::Forward {
                driver: balansir_common::DriverId::WireGuard
            }
        );

        // Unhealthy driver triggers the fallback.
        let mut health = HealthView::new();
        health.set(
            balansir_common::DriverId::WireGuard,
            balansir_common::HealthStatus::Unhealthy { reason: 1 },
        );
        let trace = engine.evaluate(&ctx_with_domain(None), &health);
        assert_eq!(trace.action, Action::Allow);
    }

    #[test]
    fn test_forward_without_fallback_under_default_deny() {
        let rules = vec![PolicyRule {
            id: 1,
            name: "dead-tunnel".to_string(),
            priority: 100,
            enabled: true,
            matcher: Matcher::Any,
            action: Action::Forward {
                driver: balansir_common::DriverId::Xray,
            },
            fallback: None,
        }];

        let engine = PolicyEngine::with_policy(rules, true);

        let mut health = HealthView::new();
        health.set(
            balansir_common::DriverId::Xray,
            balansir_common::HealthStatus::Unhealthy { reason: 2 },
        );

        // No fallback + default-deny: unmatched unhealthy forward -> Block.
        let trace = engine.evaluate(&ctx_with_domain(None), &health);
        assert_eq!(trace.action, Action::Block);

        // With a fallback present, it is preferred over default-deny.
        let rules = vec![PolicyRule {
            id: 1,
            name: "dead-tunnel-with-fallback".to_string(),
            priority: 100,
            enabled: true,
            matcher: Matcher::Any,
            action: Action::Forward {
                driver: balansir_common::DriverId::Xray,
            },
            fallback: Some(Action::Block),
        }];
        let engine = PolicyEngine::with_policy(rules, true);
        let trace = engine.evaluate(&ctx_with_domain(None), &health);
        assert_eq!(trace.action, Action::Block);
    }

    #[test]
    fn test_default_deny_blocks_unmatched() {
        let rules = vec![PolicyRule {
            id: 1,
            name: "only-specific".to_string(),
            priority: 100,
            enabled: true,
            matcher: Matcher::DomainSuffix { suffix: 999 },
            action: Action::Allow,
            fallback: None,
        }];

        // Fail-closed: traffic matching nothing is blocked.
        let engine = PolicyEngine::with_policy(rules.clone(), true);
        let trace = engine.evaluate(&ctx_with_domain(Some(424242)), &healthy());
        assert_eq!(trace.action, Action::Block);

        // Fail-open stays backward-compatible.
        let engine = PolicyEngine::new(rules);
        let trace = engine.evaluate(&ctx_with_domain(Some(424242)), &healthy());
        assert_eq!(trace.action, Action::Allow);
    }

    #[test]
    fn test_degraded_driver_also_falls_back() {
        let rules = vec![PolicyRule {
            id: 1,
            name: "degraded-pool".to_string(),
            priority: 100,
            enabled: true,
            matcher: Matcher::Any,
            action: Action::Forward {
                driver: balansir_common::DriverId::AmneziaWG,
            },
            fallback: Some(Action::Allow),
        }];

        let engine = PolicyEngine::new(rules);

        let mut health = HealthView::new();
        health.set(
            balansir_common::DriverId::AmneziaWG,
            balansir_common::HealthStatus::Degraded { reason: 1 },
        );
        let trace = engine.evaluate(&ctx_with_domain(None), &health);
        assert_eq!(trace.action, Action::Allow);
    }
}
