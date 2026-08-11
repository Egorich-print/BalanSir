//! Reconciliation: adapts the daemon to the `balansir-control` coordinator and
//! exposes the daemon-facing `Reconciler` API.

pub mod adapters;
pub mod bootstrap;
pub mod dns_flow;
pub mod dummy;
pub mod error;
pub mod executor_client;
pub mod reconciler;
pub mod sinks;

pub use crate::reconciliation::adapters::PendingMechanismAdapter;
pub use crate::reconciliation::dns_flow::{DnsRegistry, FlowCompiler};
pub use crate::reconciliation::dummy::DummyExecutorAdapter;
pub use crate::reconciliation::error::{ReconciliationError, ReconciliationResult};
pub use crate::reconciliation::executor_client::ExecutorClient;
pub use crate::reconciliation::reconciler::{ExecutorAdapter, Reconciler, ReconcilerConfig};
