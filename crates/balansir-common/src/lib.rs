pub mod diff;
pub mod error;
pub mod event_bus;
pub mod gateway;
pub mod ipc;
pub mod metrics;
pub mod network;
pub mod path_pool;
pub mod paths;
pub mod plan;
pub mod profile;
pub mod qos;
pub mod resources;
pub mod runtime;
pub mod snapshot;
pub mod state;
pub mod subsystems;
pub mod types;
pub mod validation;
pub mod version;

/// Unified path-health model lives in `balansir-health`; re-exported here so
/// the existing `balansir_common::path_health::*` imports keep working.
pub use balansir_health as path_health;
pub use diff::StateDiff;
pub use error::{DriverError, Error, Result};
pub use event_bus::BoundedEventBus;
pub use metrics::Metrics;
pub use plan::{PlanMetadata, ReconciliationOperation, ReconciliationPlan};
pub use profile::Profile;
pub use resources::ResourceAllocator;
pub use snapshot::Snapshot;
pub use types::*;
pub use validation::*;
pub use version::*;
