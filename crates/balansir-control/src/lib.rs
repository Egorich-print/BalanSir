// crates/balansir-control/src/lib.rs

//! Control Plane for BalanSir: reconciliation, planning, and execution.
//!
//! This crate provides the core interfaces and implementations for the BalanSir
//! control plane. It is designed to be used by the BalanSir daemon and other
//! components that need to interact with the control plane.

pub mod coordinator;
pub mod error;
pub mod events;
pub mod executor;
pub mod planner;
pub mod provider;
pub mod snapshot_store;
pub mod state;
pub mod traits;

pub use crate::coordinator::{Config as CoordinatorConfig, Coordinator};
pub use crate::error::{ControlError, ControlResult};
pub use crate::events::{ControlEvent, ReconcileReason};
pub use crate::state::{ExecutionReport, ReconcileProgress, ReconcileState};
pub use crate::traits::{
    DesiredProvider, EventSink, Executor, NoopEventSink, NoopRollback, Planner, Rollback,
    SnapshotStore, StateProvider,
};
