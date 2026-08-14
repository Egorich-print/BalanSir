//! Unified operational snapshot of the non-policy subsystems (QoS, network
//! interfaces, Tailscale) plus the control seam the API/WebUI use to drive
//! them.
//!
//! This is deliberately a *view model*: the daemon's subsystem managers update
//! the shared snapshot, the HTTP layer and the WebUI read it. State flows:
//!
//! ```text
//! executor (privileged)
//!     ↓ typed IPC
//! daemon subsystem managers
//!     ↓ update
//! SharedSubsystemSnapshot
//!     ↓ read
//! REST / SSE / WebUI
//! ```

use crate::network::{InterfaceInfo, InterfaceResult, TailscaleResult, TailscaleStatus};
use crate::qos::{AppliedQdisc, QosCapabilities, QosConfig};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// QoS view: what the daemon intends vs. what the kernel reports.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QosSnapshot {
    /// Shaping configurations the daemon wants applied.
    pub desired: Vec<QosConfig>,
    /// Qdiscs currently present in the kernel (executor report).
    pub applied: Vec<AppliedQdisc>,
    /// Kernel shaping capabilities probed by the executor.
    pub capabilities: Option<QosCapabilities>,
    /// True when desired and applied disagree.
    pub drift: bool,
    /// Last error encountered by the QoS manager (actionable).
    pub last_error: Option<String>,
}

/// Tailscale view: last observed status plus whether the daemon can talk to
/// the executor for operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TailscaleSnapshot {
    pub status: Option<TailscaleStatus>,
    pub error: Option<String>,
    pub pending_op: bool,
}

/// Subsystem state-change events, emitted by the daemon managers and bridged
/// to SSE for the WebUI (one event vocabulary, not one per subsystem).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubsystemEvent {
    QosApplied {
        interface: String,
        kind: String,
    },
    QosRemoved {
        interface: String,
    },
    QosDrift {
        interface: String,
        detail: String,
    },
    QosError {
        detail: String,
    },
    InterfaceMacChanged {
        interface: String,
        mac: String,
    },
    InterfaceMacRestored {
        interface: String,
    },
    InterfaceError {
        detail: String,
    },
    TailscaleStatusChanged {
        state: String,
    },
    TailscaleReconnected,
    TailscaleError {
        detail: String,
    },
}

impl SubsystemEvent {
    /// Short stable label for SSE `event:` fields and logs.
    pub fn name(&self) -> &'static str {
        match self {
            Self::QosApplied { .. } => "qos_applied",
            Self::QosRemoved { .. } => "qos_removed",
            Self::QosDrift { .. } => "qos_drift",
            Self::QosError { .. } => "qos_error",
            Self::InterfaceMacChanged { .. } => "interface_mac_changed",
            Self::InterfaceMacRestored { .. } => "interface_mac_restored",
            Self::InterfaceError { .. } => "interface_error",
            Self::TailscaleStatusChanged { .. } => "tailscale_status_changed",
            Self::TailscaleReconnected => "tailscale_reconnected",
            Self::TailscaleError { .. } => "tailscale_error",
        }
    }
}

/// A consistent point-in-time view of all non-policy subsystems.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubsystemSnapshot {
    pub qos: QosSnapshot,
    pub interfaces: Vec<InterfaceInfo>,
    pub tailscale: TailscaleSnapshot,
    /// Unix epoch millis of the last successful refresh.
    pub updated_at_ms: i64,
    /// True when the executor could not be reached for the last refresh.
    pub executor_unreachable: bool,
}

/// Shared, cloneable handle to the latest subsystem snapshot.
#[derive(Clone, Default)]
pub struct SharedSubsystemSnapshot {
    inner: Arc<RwLock<SubsystemSnapshot>>,
}

impl SharedSubsystemSnapshot {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(SubsystemSnapshot::default())),
        }
    }

    pub async fn read(&self) -> SubsystemSnapshot {
        self.inner.read().await.clone()
    }

    /// Update a single field group under the write lock.
    pub async fn update(&self, f: impl FnOnce(&mut SubsystemSnapshot)) {
        let mut guard = self.inner.write().await;
        f(&mut guard);
        guard.updated_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
    }

    /// Snapshot for tests without a runtime.
    pub fn replace(&self, snapshot: SubsystemSnapshot) {
        let mut guard = self.inner.blocking_write();
        *guard = snapshot;
    }
}

/// Control seam for the API/WebUI. Every operation is forwarded to the
/// executor over typed IPC — the WebUI never touches privileged state
/// directly.
#[async_trait::async_trait]
pub trait SubsystemControl: Send + Sync {
    /// Replace the QoS intent (empty = no shaping).
    async fn set_qos_intent(&self, configs: Vec<QosConfig>) -> Result<(), String>;
    /// Remove shaping from one interface.
    async fn remove_qos(&self, interface: &str) -> Result<(), String>;
    /// Clone a WAN MAC (factory MAC is preserved by the executor).
    async fn set_mac(&self, interface: &str, mac: &str) -> Result<InterfaceResult, String>;
    /// Restore the factory MAC.
    async fn restore_mac(&self, interface: &str) -> Result<InterfaceResult, String>;
    /// Bring the tailnet up (optional auth key).
    async fn tailscale_up(&self, auth_key: Option<String>) -> Result<TailscaleResult, String>;
    /// Take the tailnet down.
    async fn tailscale_down(&self) -> Result<TailscaleResult, String>;
    /// Reconnect to the control plane.
    async fn tailscale_reconnect(&self) -> Result<TailscaleResult, String>;
    /// Advertise subnet routes / exit node.
    async fn tailscale_set_routes(
        &self,
        routes: Vec<String>,
        exit_node: bool,
    ) -> Result<TailscaleResult, String>;
}
