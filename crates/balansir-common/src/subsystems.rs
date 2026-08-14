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

/// Per-flow B4 adaptation view (one entry per tracked flow / policy domain).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct B4FlowView {
    /// Flow key (policy domain).
    pub flow: String,
    /// Engine lifecycle state: Idle / Observing / Adapting / Monitoring /
    /// Recovered / Fallback / StrictFail.
    pub state: String,
    /// Profile the policy assigns to this flow.
    pub profile: String,
    /// Last decision, when one was made.
    pub last_decision: Option<String>,
    /// Effective path MTU the engine last decided for this flow.
    pub mtu: Option<u16>,
}

/// B4 component view: policy intent, per-flow adaptation state, ownership
/// (intended vs reported MTU), and diagnostics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct B4Snapshot {
    /// B4 adaptation enabled (from engine config).
    pub enabled: bool,
    /// Whether MTU adaptation is currently gated by policy.
    pub mtu_enabled: bool,
    /// Config file the engine was loaded from.
    pub config_path: Option<String>,
    /// Per-flow adaptation state.
    pub flows: Vec<B4FlowView>,
    /// Daemon-intended per-path MTU (ownership desired state).
    pub intended_mtu: Vec<crate::PathMtu>,
    /// Executor-reported per-path MTU (ownership actual state).
    pub reported_mtu: Vec<crate::PathMtu>,
    /// True when intended and reported disagree.
    pub drift: bool,
    /// Last engine/manager error (actionable).
    pub last_error: Option<String>,
    /// Engine enabled/disabled toggle reachable by the operator.
    pub paused: bool,
}

/// One Xray endpoint view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayProfileView {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub transport: String,
    pub tls: bool,
    /// Lower is preferred for automatic selection.
    pub priority: i32,
    pub enabled: bool,
    /// Whether this endpoint is the one currently running.
    pub active: bool,
    /// Last observed health: Unknown / Healthy / Degraded / Unhealthy.
    pub health: String,
    /// Consecutive failed health probes (drives failover).
    pub failure_count: u32,
}

/// Xray component view: endpoint profiles, the active transport endpoint,
/// selection mode, and failover/rotation diagnostics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XraySnapshot {
    pub profiles: Vec<XrayProfileView>,
    /// Name of the active endpoint, if one is running.
    pub active: Option<String>,
    /// Operator pause: the proxy process is stopped and traffic stays direct.
    pub paused: bool,
    /// Operator pinned an endpoint (manual override, still failover-aware).
    pub pinned: Option<String>,
    pub last_error: Option<String>,
    /// Local SOCKS/HTTP inbound ports of the active endpoint.
    pub socks_port: u16,
    pub http_port: u16,
    /// Why the last switch happened (actionable, e.g. "endpoint jp-2 failed 3
    /// health probes", "manual rotation").
    pub switch_reason: Option<String>,
    /// Unix epoch millis of the last switch.
    pub last_switch_ms: i64,
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
    B4StateChanged {
        flow: String,
        state: String,
    },
    B4Adapted {
        flow: String,
        capability: String,
    },
    B4Recovered {
        flow: String,
    },
    B4Drift {
        detail: String,
    },
    B4Error {
        detail: String,
    },
    XrayStarted {
        profile: String,
    },
    XrayStopped,
    XraySwitched {
        from: Option<String>,
        to: String,
        reason: String,
    },
    XrayHealthChanged {
        profile: String,
        health: String,
    },
    XrayError {
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
            Self::B4StateChanged { .. } => "b4_state_changed",
            Self::B4Adapted { .. } => "b4_adapted",
            Self::B4Recovered { .. } => "b4_recovered",
            Self::B4Drift { .. } => "b4_drift",
            Self::B4Error { .. } => "b4_error",
            Self::XrayStarted { .. } => "xray_started",
            Self::XrayStopped => "xray_stopped",
            Self::XraySwitched { .. } => "xray_switched",
            Self::XrayHealthChanged { .. } => "xray_health_changed",
            Self::XrayError { .. } => "xray_error",
        }
    }
}

/// A consistent point-in-time view of all non-policy subsystems.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubsystemSnapshot {
    pub qos: QosSnapshot,
    pub interfaces: Vec<InterfaceInfo>,
    pub tailscale: TailscaleSnapshot,
    pub b4: B4Snapshot,
    pub xray: XraySnapshot,
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
    /// Pause/resume the B4 adaptation engine (no config change, just the loop).
    async fn b4_set_paused(&self, paused: bool) -> Result<(), String>;
    /// Whether the B4 engine is currently paused.
    async fn b4_is_paused(&self) -> bool;
    /// Pause/resume the Xray transport (stop/start the proxy process).
    async fn xray_set_paused(&self, paused: bool) -> Result<(), String>;
    /// Whether the Xray transport is currently paused.
    async fn xray_is_paused(&self) -> bool;
    /// Pin a specific Xray endpoint (manual override; failover-aware).
    async fn xray_select(&self, profile: &str) -> Result<(), String>;
    /// Rotate to the next enabled endpoint (manual rotation).
    async fn xray_rotate(&self) -> Result<(), String>;
}
