// crates/balansir-common/src/diff.rs

use crate::plan::{ReconciliationOperation, ReconciliationPlan};
use crate::{ActualState, DesiredState};

pub struct StateDiff;

impl StateDiff {
    /// Build a reconciliation plan by comparing desired state against actual state.
    pub fn build(
        desired: &DesiredState,
        actual: &ActualState,
        current_generation: u64,
    ) -> ReconciliationPlan {
        let mut operations = Vec::new();

        // 1. Check rules to add or update
        for rule in &desired.rules {
            match actual.active_rules.iter().find(|r| r.id == rule.id) {
                Some(ar) if ar.action == rule.action => {
                    // Already in desired state and action matches -> NoOp
                }
                Some(_) => {
                    // Rule exists but action changed -> Update
                    operations.push(ReconciliationOperation::UpdatePolicy(rule.clone()));
                }
                None => {
                    // Rule missing -> Create/Apply
                    operations.push(ReconciliationOperation::UpdatePolicy(rule.clone()));
                }
            }
        }

        // 2. Check rules to remove (extra rules in actual state that are not in desired state)
        for actual_rule in &actual.active_rules {
            if !desired.rules.iter().any(|r| r.id == actual_rule.id) {
                operations.push(ReconciliationOperation::RemovePolicy(actual_rule.id));
            }
        }

        if operations.is_empty() {
            operations.push(ReconciliationOperation::NoOp);
        }

        ReconciliationPlan::new(current_generation, operations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, ActualRule, DesiredRule};

    #[test]
    fn test_diff_no_changes() {
        let desired = DesiredState {
            rules: vec![DesiredRule {
                id: 1,
                action: Action::Allow,
                priority: 10,
            }],
            drivers: vec![],
        };
        let actual = ActualState {
            active_rules: vec![ActualRule {
                id: 1,
                action: Action::Allow,
                rule_id: Some(1),
            }],
        };

        let plan = StateDiff::build(&desired, &actual, 10);
        assert!(plan.is_empty());
        assert_eq!(plan.generation_before, 10);
        assert_eq!(plan.generation_after, 10);
    }

    #[test]
    fn test_diff_add_rule() {
        let desired = DesiredState {
            rules: vec![DesiredRule {
                id: 1,
                action: Action::Allow,
                priority: 10,
            }],
            drivers: vec![],
        };
        let actual = ActualState {
            active_rules: vec![],
        };

        let plan = StateDiff::build(&desired, &actual, 5);
        assert_eq!(plan.operations.len(), 1);
        assert_eq!(plan.generation_before, 5);
        assert_eq!(plan.generation_after, 6);
        match &plan.operations[0] {
            ReconciliationOperation::UpdatePolicy(rule) => assert_eq!(rule.id, 1),
            _ => panic!("Expected UpdatePolicy"),
        }
    }
}
