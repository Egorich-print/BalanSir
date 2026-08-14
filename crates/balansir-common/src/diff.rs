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
                Some(ar) if ar.action == rule.action && ar.flow == rule.flow => {
                    // Already in desired state and action + flow match -> NoOp
                }
                Some(_) => {
                    // Rule exists but action or flow criteria changed -> Update
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
                flow: None,
            }],
            drivers: vec![],
            qos: vec![],
        };
        let actual = ActualState {
            active_rules: vec![ActualRule {
                id: 1,
                action: Action::Allow,
                rule_id: Some(1),
                flow: None,
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
                flow: None,
            }],
            drivers: vec![],
            qos: vec![],
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

    /// M3.4.4: golden plan fixture. Given fixed desired/actual state, the
    /// operation sequence is exact and deterministic — this pins the diff
    /// contract so a future planner change that alters operation ordering or
    /// identity fails loudly.
    #[test]
    fn golden_plan_fixture_is_deterministic() {
        let desired = DesiredState {
            rules: vec![
                DesiredRule {
                    id: 1,
                    action: Action::Block,
                    priority: 100,
                    flow: None,
                },
                DesiredRule {
                    id: 2,
                    action: Action::Allow,
                    priority: 50,
                    flow: None,
                },
            ],
            drivers: Vec::new(),
            qos: Vec::new(),
        };
        // Actual already carries rule 2 (Allow); rule 3 is stale and must be
        // removed.
        let actual = ActualState {
            active_rules: vec![
                ActualRule {
                    id: 2,
                    action: Action::Allow,
                    rule_id: Some(20),
                    flow: None,
                },
                ActualRule {
                    id: 3,
                    action: Action::Block,
                    rule_id: Some(30),
                    flow: None,
                },
            ],
        };

        let plan = StateDiff::build(&desired, &actual, 42);
        let golden: Vec<ReconciliationOperation> = vec![
            // Rule 1 missing from actual -> apply.
            ReconciliationOperation::UpdatePolicy(DesiredRule {
                id: 1,
                action: Action::Block,
                priority: 100,
                flow: None,
            }),
            // Rule 3 in actual but not desired -> remove.
            ReconciliationOperation::RemovePolicy(3),
        ];

        assert_eq!(plan.operations, golden);
        assert_eq!(plan.generation_before, 42);
        assert_eq!(plan.generation_after, 43);

        // Deterministic: rebuilding yields the identical plan.
        let again = StateDiff::build(&desired, &actual, 42);
        assert_eq!(again.operations, plan.operations);
        assert_eq!(again.generation_before, plan.generation_before);
        assert_eq!(again.generation_after, plan.generation_after);
    }

    /// M3.4.4: operation ordering is stable — desired rules are visited in
    /// declaration order and removals in actual order, so identical inputs
    /// always produce identical operation sequences (no HashMap iteration).
    #[test]
    fn operation_order_is_stable_and_repeatable() {
        let desired = DesiredState {
            rules: vec![
                DesiredRule {
                    id: 10,
                    action: Action::Allow,
                    priority: 10,
                    flow: None,
                },
                DesiredRule {
                    id: 20,
                    action: Action::Block,
                    priority: 20,
                    flow: None,
                },
                DesiredRule {
                    id: 30,
                    action: Action::Reject,
                    priority: 30,
                    flow: None,
                },
            ],
            drivers: Vec::new(),
            qos: Vec::new(),
        };
        let actual = ActualState {
            active_rules: vec![
                ActualRule {
                    id: 40,
                    action: Action::Allow,
                    rule_id: None,
                    flow: None,
                },
                ActualRule {
                    id: 10,
                    action: Action::Allow,
                    rule_id: Some(10),
                    flow: None,
                },
            ],
        };

        let a = StateDiff::build(&desired, &actual, 1);
        let b = StateDiff::build(&desired, &actual, 1);
        assert_eq!(a.operations, b.operations);

        // Expect: add rule 20, add rule 30 (rule 10 matches actual, no-op),
        // remove rule 40 (not desired). Order reflects desired-then-actual.
        assert_eq!(a.operations.len(), 3);
        assert!(matches!(
            &a.operations[0],
            ReconciliationOperation::UpdatePolicy(r) if r.id == 20
        ));
        assert!(matches!(
            &a.operations[1],
            ReconciliationOperation::UpdatePolicy(r) if r.id == 30
        ));
        assert!(matches!(
            &a.operations[2],
            ReconciliationOperation::RemovePolicy(40)
        ));
    }

    /// A3 (ADR-018): flow criteria are part of rule identity. Same id + same
    /// action but different flow → UpdatePolicy, not NoOp.
    #[test]
    fn flow_criteria_change_triggers_update() {
        use crate::FlowCriteria;
        let with_flow = |ip: u8| DesiredRule {
            id: 7,
            action: Action::Block,
            priority: 100,
            flow: Some(FlowCriteria {
                dst_ip: Some(std::net::IpAddr::from([203, 0, 113, ip])),
                ..Default::default()
            }),
        };

        // Actual has the old flow; desired has a different flow.
        let desired = DesiredState {
            rules: vec![with_flow(6)],
            drivers: vec![],
            qos: vec![],
        };
        let actual = ActualState {
            active_rules: vec![ActualRule {
                id: 7,
                action: Action::Block,
                rule_id: Some(1),
                flow: Some(FlowCriteria {
                    dst_ip: Some(std::net::IpAddr::from([203, 0, 113, 5])),
                    ..Default::default()
                }),
            }],
        };
        let plan = StateDiff::build(&desired, &actual, 1);
        assert_eq!(plan.operations.len(), 1);
        assert!(matches!(
            &plan.operations[0],
            ReconciliationOperation::UpdatePolicy(r) if r.id == 7
        ));

        // Same id + action + flow -> NoOp.
        let same = ActualState {
            active_rules: vec![ActualRule {
                id: 7,
                action: Action::Block,
                rule_id: Some(1),
                flow: with_flow(6).flow.clone(),
            }],
        };
        assert!(StateDiff::build(&desired, &same, 1).is_empty());
    }
}
