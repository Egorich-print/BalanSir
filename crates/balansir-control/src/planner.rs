// crates/balansir-control/src/planner.rs

use crate::traits::Planner;
use balansir_common::{ActualState, DesiredState, ReconciliationPlan, StateDiff};

/// Deterministic planner: delegates to `StateDiff::build`.
///
/// The produced plan carries generation metadata computed from the diff, and
/// contains a minimal ordered set of operations to converge actual -> desired.
#[derive(Debug, Default, Clone, Copy)]
pub struct BasicPlanner;

impl Planner for BasicPlanner {
    fn build_plan(
        &self,
        desired: &DesiredState,
        actual: &ActualState,
        generation: u64,
    ) -> ReconciliationPlan {
        StateDiff::build(desired, actual, generation)
    }
}
