// crates/balansir-daemon/src/reconciliation/plan.rs

use balansir_common::{DesiredRule, DriverId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationOperation {
    CreateDriver(DriverId),
    RemoveDriver(DriverId),
    RestartDriver(DriverId),
    UpdatePolicy(DesiredRule),
    RemovePolicy(u32), // by rule ID
    NoOp,
}

#[derive(Debug, Clone)]
pub struct ReconciliationPlan {
    pub operations: Vec<ReconciliationOperation>,
}

impl ReconciliationPlan {
    pub fn new(operations: Vec<ReconciliationOperation>) -> Self {
        Self { operations }
    }
    
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty() || self.operations.iter().all(|op| matches!(op, ReconciliationOperation::NoOp))
    }
}
