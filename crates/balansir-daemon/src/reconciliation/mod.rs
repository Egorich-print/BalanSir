//! Reconciliation: adapts the daemon to the `balansir-control` coordinator and
//! exposes the daemon-facing `Reconciler` API.

pub mod adapters;
pub mod bootstrap;
pub mod dummy;
pub mod reconciler;
pub mod sinks;

pub use crate::reconciliation::dummy::DummyExecutorAdapter;
pub use crate::reconciliation::reconciler::{ExecutorAdapter, Reconciler, ReconcilerConfig};
