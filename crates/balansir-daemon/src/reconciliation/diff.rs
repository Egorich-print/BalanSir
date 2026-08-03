use balansir_common::{DesiredState, DesiredRule};
use crate::reconciliation::ActualState;
use crate::reconciliation::plan::{ReconciliationPlan, ReconciliationOperation};

pub struct StateDiff;

impl StateDiff {
    pub fn build(desired: &DesiredState, actual: &ActualState) -> ReconciliationPlan {
        let mut ops = Vec::new();

        // 1. Check for Missing or Changed rules
        for rule in &desired.rules {
            match actual.active_rules.iter().find(|ar| ar.id == rule.id) {
                Some(ar) if ar.action == rule.action => {
                    // Consistent, NoOp
                }
                Some(_) => {
                    // Changed
                    ops.push(ReconciliationOperation::UpdatePolicy(rule.clone()));
                }
                None => {
                    // Missing
                    ops.push(ReconciliationOperation::UpdatePolicy(rule.clone()));
                }
            }
        }

        // 2. Check for Extra rules
        for actual_rule in &actual.active_rules {
            if !desired.rules.iter().any(|r| r.id == actual_rule.id) {
                ops.push(ReconciliationOperation::RemovePolicy(actual_rule.id));
            }
        }

        ReconciliationPlan::new(ops)
    }
}
