// crates/balansir-common/src/snapshot.rs

use crate::plan::PlanMetadata;
use crate::{ActualState, DesiredState};
use serde::{Deserialize, Serialize};

/// A consistent point-in-time snapshot: desired + actual + plan metadata.
///
/// Used for rollback (restore previous snapshot) and crash recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub desired: DesiredState,
    pub actual: ActualState,
    pub metadata: PlanMetadata,
}

impl Snapshot {
    pub fn new(desired: DesiredState, actual: ActualState, metadata: PlanMetadata) -> Self {
        Self {
            desired,
            actual,
            metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::ReconciliationPlan;
    use crate::{Action, DesiredRule};

    #[test]
    fn test_snapshot_roundtrip_postcard() {
        let snapshot = Snapshot {
            desired: DesiredState {
                rules: vec![DesiredRule {
                    id: 1,
                    action: Action::Allow,
                    priority: 10,
                }],
                drivers: vec![],
            },
            actual: ActualState {
                active_rules: vec![crate::ActualRule {
                    id: 1,
                    action: Action::Allow,
                    rule_id: Some(1),
                }],
            },
            metadata: PlanMetadata::new(1),
        };

        let encoded = postcard::to_allocvec(&snapshot).unwrap();
        let decoded: Snapshot = postcard::from_bytes(&encoded).unwrap();

        assert_eq!(decoded.desired.rules.len(), 1);
        assert_eq!(decoded.actual.active_rules.len(), 1);
        assert_eq!(decoded.metadata.generation, 1);
        assert_eq!(decoded.metadata.plan_id, snapshot.metadata.plan_id);
    }

    #[test]
    fn test_plan_roundtrip_json() {
        let plan = ReconciliationPlan::new(
            3,
            vec![crate::plan::ReconciliationOperation::UpdatePolicy(
                DesiredRule {
                    id: 42,
                    action: Action::Block,
                    priority: 100,
                },
            )],
        );

        let json = serde_json::to_string(&plan).unwrap();
        let decoded: ReconciliationPlan = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.generation_before, 3);
        assert_eq!(decoded.generation_after, 4);
        assert_eq!(decoded.operations.len(), 1);
    }
}
