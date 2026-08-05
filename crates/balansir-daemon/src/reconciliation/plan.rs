// crates/balansir-daemon/src/reconciliation/plan.rs

use balansir_common::{DesiredRule, DriverId};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ReconciliationOperation {
    CreateDriver(DriverId),
    RemoveDriver(DriverId),
    RestartDriver(DriverId),
    UpdatePolicy(DesiredRule),
    RemovePolicy(u32), // by rule ID
    NoOp,
}

impl fmt::Display for ReconciliationOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CreateDriver(id) => write!(f, "+ Create driver {:?}", id),
            Self::RemoveDriver(id) => write!(f, "- Remove driver {:?}", id),
            Self::RestartDriver(id) => write!(f, "~ Restart driver {:?}", id),
            Self::UpdatePolicy(rule) => write!(f, "~ Update policy {:?}", rule.id),
            Self::RemovePolicy(id) => write!(f, "- Remove policy {}", id),
            Self::NoOp => write!(f, "NoOp"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReconciliationPlan {
    pub generation_before: u64,
    pub generation_after: u64,
    pub operations: Vec<ReconciliationOperation>,
}

impl ReconciliationPlan {
    pub fn new(gen_before: u64, operations: Vec<ReconciliationOperation>) -> Self {
        let generation_after = if operations
            .iter()
            .any(|op| !matches!(op, ReconciliationOperation::NoOp))
        {
            gen_before + 1
        } else {
            gen_before
        };

        Self {
            generation_before: gen_before,
            generation_after,
            operations,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
            || self
                .operations
                .iter()
                .all(|op| matches!(op, ReconciliationOperation::NoOp))
    }
}

impl fmt::Display for ReconciliationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Configuration generation: {} -> {}",
            self.generation_before, self.generation_after
        )?;

        if self.is_empty() {
            writeln!(f, "\nNo operations needed.")?;
            return Ok(());
        }

        writeln!(f, "\nOperations:")?;
        for op in &self.operations {
            if !matches!(op, ReconciliationOperation::NoOp) {
                writeln!(f, "  {}", op)?;
            }
        }

        let created = self
            .operations
            .iter()
            .filter(|op| matches!(op, ReconciliationOperation::CreateDriver(_)))
            .count();
        let restarted = self
            .operations
            .iter()
            .filter(|op| matches!(op, ReconciliationOperation::RestartDriver(_)))
            .count();
        let updated = self
            .operations
            .iter()
            .filter(|op| matches!(op, ReconciliationOperation::UpdatePolicy(_)))
            .count();
        let removed = self
            .operations
            .iter()
            .filter(|op| {
                matches!(op, ReconciliationOperation::RemovePolicy(_))
                    || matches!(op, ReconciliationOperation::RemoveDriver(_))
            })
            .count();

        writeln!(f, "\nSummary:")?;
        writeln!(f, "  Drivers created: {}", created)?;
        writeln!(f, "  Drivers restarted: {}", restarted)?;
        writeln!(f, "  Policies updated: {}", updated)?;
        writeln!(f, "  Items removed: {}", removed)?;

        Ok(())
    }
}
