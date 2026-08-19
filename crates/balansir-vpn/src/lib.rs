//! BalanSir VPN pool — health-aware alternative-path management.
//!
//! A pool of validated VPN endpoint profiles with deterministic, explainable
//! selection: weighted by health (unified `PathHealth`), cooldown-aware,
//! recovery with ramp-up, flow stickiness, and capacity-aware load
//! distribution. This is the decision engine the Xray manager consumes — the
//! Xray manager no longer decides priority/health on its own.

pub mod importer;
pub mod pool;
pub mod profile;
pub mod uri;

pub use importer::{import_subscription, ImportResult, RejectedProfile};
pub use pool::{PoolConfig, PoolSnapshot, SelectionDecision, VpnPool};
pub use profile::{ProfileHealth, ProfileState, Protocol, Security, Transport, VpnProfile};
