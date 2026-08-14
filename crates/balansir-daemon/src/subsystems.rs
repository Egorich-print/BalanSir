//! Daemon-side subsystem managers: QoS shaping, network interfaces (WAN
//! identity), and Tailscale.
//!
//! Each manager is a small ownership loop in the same spirit as the policy
//! reconciler: the daemon holds intent, drives the privileged executor over
//! typed IPC, observes what the kernel actually reports, and converges the
//! two. All observations land in a shared `SharedSubsystemSnapshot` that the
//! REST/SSE layer and the WebUI read; state changes emit `SubsystemEvent`s.
//!
//! There is deliberately no second metrics/state system here: the snapshot
//! *is* the unified view, and events *are* the unified event vocabulary.

use async_trait::async_trait;
use balansir_common::network::{
    InterfaceInfo, InterfaceResult, TailscaleResult, TailscaleStatus,
};
use balansir_common::qos::{AppliedQdisc, QosCapabilities, QosConfig, QosDirection, QosOp, QosResult};
use balansir_common::subsystems::{
    QosSnapshot, SharedSubsystemSnapshot, SubsystemEvent, TailscaleSnapshot,
};
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

use crate::reconciliation::ExecutorClient;

/// Narrow executor view used by the subsystem managers. Implemented by the
/// real IPC client and by fakes in tests — the managers never know the socket.
#[async_trait]
pub trait SubsystemExec: Send + Sync {
    async fn qos_op(&self, op: &QosOp) -> Result<QosResult, String>;
    async fn qos_state(&self, interface: &str) -> Result<Vec<AppliedQdisc>, String>;
    async fn qos_capabilities(&self) -> Result<QosCapabilities, String>;
    async fn interface_info(&self, interface: &str) -> Result<Vec<InterfaceInfo>, String>;
    async fn interface_set_mac(&self, interface: &str, mac: &str) -> Result<InterfaceResult, String>;
    async fn interface_restore_mac(&self, interface: &str) -> Result<InterfaceResult, String>;
    async fn tailscale_status(&self) -> Result<TailscaleStatus, String>;
    async fn tailscale_up(&self, auth_key: Option<String>) -> Result<TailscaleResult, String>;
    async fn tailscale_down(&self) -> Result<TailscaleResult, String>;
    async fn tailscale_reconnect(&self) -> Result<TailscaleResult, String>;
    async fn tailscale_set_routes(
        &self,
        routes: &[String],
        exit_node: bool,
    ) -> Result<TailscaleResult, String>;
}

#[async_trait]
impl SubsystemExec for ExecutorClient {
    async fn qos_op(&self, op: &QosOp) -> Result<QosResult, String> {
        self.qos_op(op).await.map_err(|e| e.to_string())
    }
    async fn qos_state(&self, interface: &str) -> Result<Vec<AppliedQdisc>, String> {
        self.qos_state(interface).await.map_err(|e| e.to_string())
    }
    async fn qos_capabilities(&self) -> Result<QosCapabilities, String> {
        self.qos_capabilities().await.map_err(|e| e.to_string())
    }
    async fn interface_info(&self, interface: &str) -> Result<Vec<InterfaceInfo>, String> {
        self.interface_info(interface).await.map_err(|e| e.to_string())
    }
    async fn interface_set_mac(&self, interface: &str, mac: &str) -> Result<InterfaceResult, String> {
        self.interface_set_mac(interface, mac).await.map_err(|e| e.to_string())
    }
    async fn interface_restore_mac(&self, interface: &str) -> Result<InterfaceResult, String> {
        self.interface_restore_mac(interface).await.map_err(|e| e.to_string())
    }
    async fn tailscale_status(&self) -> Result<TailscaleStatus, String> {
        self.tailscale_status().await.map_err(|e| e.to_string())
    }
    async fn tailscale_up(&self, auth_key: Option<String>) -> Result<TailscaleResult, String> {
        self.tailscale_up(auth_key).await.map_err(|e| e.to_string())
    }
    async fn tailscale_down(&self) -> Result<TailscaleResult, String> {
        self.tailscale_down().await.map_err(|e| e.to_string())
    }
    async fn tailscale_reconnect(&self) -> Result<TailscaleResult, String> {
        self.tailscale_reconnect().await.map_err(|e| e.to_string())
    }
    async fn tailscale_set_routes(
        &self,
        routes: &[String],
        exit_node: bool,
    ) -> Result<TailscaleResult, String> {
        self.tailscale_set_routes(routes, exit_node)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Default refresh cadence for subsystem observation.
const SUBSYSTEM_INTERVAL_SECS: u64 = 5;

/// Subsystem managers bundle: owns the shared snapshot, the executor view,
/// and the event broadcaster. One handle the daemon and the API can share.
pub struct SubsystemManager {
    exec: Arc<dyn SubsystemExec>,
    snapshot: SharedSubsystemSnapshot,
    qos_intent: RwLock<Vec<QosConfig>>,
    events: broadcast::Sender<SubsystemEvent>,
    interface_filter: RwLock<String>,
}

impl SubsystemManager {
    pub fn new(exec: Arc<dyn SubsystemExec>) -> Self {
        let (events, _) = broadcast::channel(128);
        Self {
            exec,
            snapshot: SharedSubsystemSnapshot::new(),
            qos_intent: RwLock::new(Vec::new()),
            events,
            interface_filter: RwLock::new(String::new()),
        }
    }

    pub fn snapshot(&self) -> SharedSubsystemSnapshot {
        self.snapshot.clone()
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<SubsystemEvent> {
        self.events.subscribe()
    }

    /// Clone the event sender (for SSE wiring).
    pub fn event_sender(&self) -> broadcast::Sender<SubsystemEvent> {
        self.events.clone()
    }

    fn emit(&self, event: SubsystemEvent) {
        let _ = self.events.send(event);
    }

    /// Set which interfaces are reported (empty = all).
    pub async fn set_interface_filter(&self, filter: String) {
        *self.interface_filter.write().await = filter;
    }

    /// Replace the QoS intent and trigger an immediate convergence pass.
    pub async fn set_qos_intent(&self, configs: Vec<QosConfig>) -> Result<(), String> {
        *self.qos_intent.write().await = configs;
        self.converge_qos().await
    }

    /// Remove shaping from one interface.
    pub async fn remove_qos(&self, interface: &str) -> Result<(), String> {
        let mut intent = self.qos_intent.write().await;
        intent.retain(|c| c.interface != interface);
        drop(intent);
        self.converge_qos().await
    }

    /// One observation + convergence pass. Public for tests and manual
    /// triggers.
    pub async fn refresh(&self) {
        let exec = &*self.exec;
        let mut unreachable = false;

        // Interfaces ------------------------------------------------------
        let filter = self.interface_filter.read().await.clone();
        match exec.interface_info(&filter).await {
            Ok(list) => {
                self.snapshot
                    .update(|s| s.interfaces = list).await;
                debug!("subsystems: interface refresh ok");
            }
            Err(e) => {
                unreachable = true;
                warn!("subsystems: interface refresh failed: {e}");
                self.emit(SubsystemEvent::InterfaceError {
                    detail: format!("interface refresh: {e}"),
                });
            }
        }

        // QoS -------------------------------------------------------------
        let qos_err = self.converge_qos().await.err();

        // Tailscale -------------------------------------------------------
        let tail_prev = self.snapshot.read().await.tailscale.status;
        match exec.tailscale_status().await {
            Ok(status) => {
                let changed = tail_prev
                    .as_ref()
                    .map(|p| {
                        p.backend_state != status.backend_state
                            || p.self_online != status.self_online
                    })
                    .unwrap_or(true);
                self.snapshot.update(|s| {
                    s.tailscale = TailscaleSnapshot {
                        status: Some(status.clone()),
                        error: None,
                        pending_op: false,
                    }
                }).await;
                if changed {
                    let state = if status.backend_state.is_empty() {
                        "Unknown".to_string()
                    } else {
                        status.backend_state.clone()
                    };
                    info!("subsystems: tailscale state → {state}");
                    self.emit(SubsystemEvent::TailscaleStatusChanged { state });
                }
            }
            Err(e) => {
                unreachable = true;
                self.snapshot.update(|s| {
                    s.tailscale = TailscaleSnapshot {
                        status: tail_prev,
                        error: Some(e.clone()),
                        pending_op: false,
                    }
                }).await;
                self.emit(SubsystemEvent::TailscaleError { detail: e });
            }
        }

        self.snapshot
            .update(|s| s.executor_unreachable = unreachable).await;

        if let Some(err) = qos_err {
            warn!("subsystems: QoS convergence failed: {err}");
        }
    }

    /// Run the periodic observation loop until the task is aborted.
    pub async fn run_loop(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
            SUBSYSTEM_INTERVAL_SECS,
        ));
        loop {
            ticker.tick().await;
            self.refresh().await;
        }
    }

    /// Converge QoS intent against the executor's reported qdiscs.
    async fn converge_qos(&self) -> Result<(), String> {
        let exec = &*self.exec;
        let (desired, applied, caps) = match (exec.qos_state("").await, exec.qos_capabilities().await)
        {
            (Ok(applied), Ok(caps)) => {
                let desired = self.qos_intent.read().await.clone();
                (desired, applied, Some(caps))
            }
            (Err(e), _) | (_, Err(e)) => {
                self.snapshot.update(|s| {
                    s.qos.last_error = Some(e.clone());
                    s.qos.drift = true;
                }).await;
                return Err(e);
            }
        };

        // Fail loudly for unsupported kinds instead of silently degrading.
        for config in &desired {
            let supported = match config.kind {
                balansir_common::qos::QdiscKind::Cake => caps.as_ref().map(|c| c.cake).unwrap_or(false),
                balansir_common::qos::QdiscKind::FqCodel => caps
                    .as_ref()
                    .map(|c| c.fq_codel)
                    .unwrap_or(false),
                balansir_common::qos::QdiscKind::Ingress => caps
                    .as_ref()
                    .map(|c| c.ingress)
                    .unwrap_or(false),
            };
            if !supported {
                let detail = format!(
                    "{} not supported on {} (kernel/module missing)",
                    config.kind.as_str(),
                    config.interface
                );
                self.snapshot.update(|s| {
                    s.qos.last_error = Some(detail.clone());
                    s.qos.drift = true;
                }).await;
                self.emit(SubsystemEvent::QosError {
                    detail: detail.clone(),
                });
                return Err(detail);
            }
        }

        // Orphan cleanup: remove our qdiscs on interfaces no longer desired.
        let desired_interfaces: Vec<&str> = desired.iter().map(|c| c.interface.as_str()).collect();
        for q in &applied {
            if q.our_identity && !desired_interfaces.contains(&q.interface.as_str()) {
                info!(
                    "subsystems: removing orphan qdisc on {} ({}:{})",
                    q.interface,
                    q.handle,
                    q.kind.as_deref().unwrap_or("?")
                );
                match exec
                    .qos_op(&QosOp::Remove {
                        interface: q.interface.clone(),
                    })
                    .await
                {
                    Ok(_) => {
                        self.emit(SubsystemEvent::QosRemoved {
                            interface: q.interface.clone(),
                        });
                    }
                    Err(e) => {
                        let detail = format!("orphan cleanup {}: {e}", q.interface);
                        self.emit(SubsystemEvent::QosError {
                            detail: detail.clone(),
                        });
                        self.snapshot.update(|s| s.qos.last_error = Some(detail)).await;
                    }
                }
            }
        }

        // Apply or replace where desired and applied disagree.
        for config in &desired {
            let match_found = applied.iter().any(|q| {
                q.our_identity
                    && q.interface == config.interface
                    && q.kind.as_deref() == Some(config.kind.as_str())
            });
            if !match_found {
                info!(
                    "subsystems: applying {} on {}",
                    config.kind.as_str(),
                    config.interface
                );
                match exec.qos_op(&QosOp::Apply(config.clone()))
                    .await
                {
                    Ok(_) => {
                        self.emit(SubsystemEvent::QosApplied {
                            interface: config.interface.clone(),
                            kind: config.kind.as_str().to_string(),
                        });
                    }
                    Err(e) => {
                        let detail = format!(
                            "apply {} on {}: {e}",
                            config.kind.as_str(),
                            config.interface
                        );
                        self.emit(SubsystemEvent::QosError {
                            detail: detail.clone(),
                        });
                        self.snapshot.update(|s| s.qos.last_error = Some(detail)).await;
                    }
                }
            }
        }

        let applied_fresh = exec.qos_state("").await.unwrap_or(applied);
        let drift_now = desired
            .iter()
            .any(|config| {
                !applied_fresh.iter().any(|q| {
                    q.our_identity
                        && q.interface == config.interface
                        && q.kind.as_deref() == Some(config.kind.as_str())
                })
            })
            || applied_fresh.iter().any(|q| {
                q.our_identity
                    && !desired.iter().any(|c| {
                        c.interface == q.interface && c.kind.as_str() == q.kind.as_deref().unwrap_or("")
                    })
            });

        self.snapshot.update(|s| {
            s.qos = QosSnapshot {
                desired: desired.clone(),
                applied: applied_fresh,
                capabilities: caps,
                drift: drift_now,
                last_error: None,
            };
        }).await;

        Ok(())
    }
}

/// `SubsystemControl` implementation for the API/WebUI. All operations go
/// through the executor; intent is updated first so reconciliation converges
/// even if the executor is briefly unreachable.
pub struct ControlImpl {
    manager: Arc<SubsystemManager>,
}

impl ControlImpl {
    pub fn new(manager: Arc<SubsystemManager>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl balansir_common::subsystems::SubsystemControl for ControlImpl {
    async fn set_qos_intent(&self, configs: Vec<QosConfig>) -> Result<(), String> {
        self.manager.set_qos_intent(configs).await
    }

    async fn remove_qos(&self, interface: &str) -> Result<(), String> {
        self.manager.remove_qos(interface).await
    }

    async fn set_mac(&self, interface: &str, mac: &str) -> Result<InterfaceResult, String> {
        let result = self.manager.exec.interface_set_mac(interface, mac).await?;
        self.manager.emit(SubsystemEvent::InterfaceMacChanged {
            interface: interface.to_string(),
            mac: mac.to_string(),
        });
        self.manager.refresh().await;
        Ok(result)
    }

    async fn restore_mac(&self, interface: &str) -> Result<InterfaceResult, String> {
        let result = self
            .manager
            .exec
            .interface_restore_mac(interface)
            .await?;
        self.manager.emit(SubsystemEvent::InterfaceMacRestored {
            interface: interface.to_string(),
        });
        self.manager.refresh().await;
        Ok(result)
    }

    async fn tailscale_up(&self, auth_key: Option<String>) -> Result<TailscaleResult, String> {
        let result = self.manager.exec.tailscale_up(auth_key).await?;
        self.manager.refresh().await;
        Ok(result)
    }

    async fn tailscale_down(&self) -> Result<TailscaleResult, String> {
        let result = self.manager.exec.tailscale_down().await?;
        self.manager.refresh().await;
        Ok(result)
    }

    async fn tailscale_reconnect(&self) -> Result<TailscaleResult, String> {
        let result = self.manager.exec.tailscale_reconnect().await?;
        self.manager.emit(SubsystemEvent::TailscaleReconnected);
        self.manager.refresh().await;
        Ok(result)
    }

    async fn tailscale_set_routes(
        &self,
        routes: Vec<String>,
        exit_node: bool,
    ) -> Result<TailscaleResult, String> {
        let result = self
            .manager
            .exec
            .tailscale_set_routes(&routes, exit_node)
            .await?;
        self.manager.refresh().await;
        Ok(result)
    }
}

/// Simple QoS intent, validated. Enables config-file driven shaping.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QosIntentToml {
    pub interface: String,
    pub kind: Option<String>,
    pub direction: Option<String>,
    pub bandwidth_mbps: Option<u64>,
    pub latency_target_ms: Option<u64>,
}

pub fn qos_intent_from_toml(entries: &[QosIntentToml]) -> Result<Vec<QosConfig>, String> {
    let mut out = Vec::new();
    for entry in entries {
        if entry.interface.trim().is_empty() {
            return Err("qos interface must not be empty".into());
        }
        let kind = match entry.kind.as_deref().unwrap_or("fq_codel") {
            "fq_codel" => balansir_common::qos::QdiscKind::FqCodel,
            "cake" => balansir_common::qos::QdiscKind::Cake,
            "ingress" => balansir_common::qos::QdiscKind::Ingress,
            other => return Err(format!("unsupported qdisc kind: {other}")),
        };
        let direction = match entry.direction.as_deref().unwrap_or("egress") {
            "egress" => QosDirection::Egress,
            "ingress" => QosDirection::Ingress,
            other => return Err(format!("unsupported qos direction: {other}")),
        };
        out.push(QosConfig {
            interface: entry.interface.trim().to_string(),
            direction,
            kind,
            bandwidth_bps: entry.bandwidth_mbps.map(|m| m * 1_000_000),
            latency_target_ms: entry.latency_target_ms,
            overhead_bytes: None,
            ecn: true,
            wash: false,
            memory_limit_bytes: None,
            classes: vec![],
            comment: QosConfig::identity(entry.interface.trim()),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::qos::{QdiscKind, QosCapabilities};

    struct FakeExec {
        applied: std::sync::Mutex<Vec<AppliedQdisc>>,
    }

    impl FakeExec {
        fn new() -> Self {
            Self {
                applied: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl SubsystemExec for FakeExec {
        async fn qos_op(&self, op: &QosOp) -> Result<QosResult, String> {
            match op {
                QosOp::Apply(config) => {
                    let mut applied = self.applied.lock().unwrap();
                    applied.retain(|q| q.interface != config.interface);
                    applied.push(AppliedQdisc {
                        interface: config.interface.clone(),
                        index: 1,
                        handle: "b51:0".into(),
                        parent: "ffff:fff1".into(),
                        kind: Some(config.kind.as_str().to_string()),
                        our_identity: true,
                        stats: None,
                    });
                    Ok(QosResult {
                        op: "apply".into(),
                        interface: config.interface.clone(),
                        ok: true,
                        detail: "applied".into(),
                    })
                }
                QosOp::Remove { interface } => {
                    self.applied.lock().unwrap().retain(|q| q.interface != *interface);
                    Ok(QosResult {
                        op: "remove".into(),
                        interface: interface.clone(),
                        ok: true,
                        detail: "removed".into(),
                    })
                }
            }
        }
        async fn qos_state(&self, _interface: &str) -> Result<Vec<AppliedQdisc>, String> {
            Ok(self.applied.lock().unwrap().clone())
        }
        async fn qos_capabilities(&self) -> Result<QosCapabilities, String> {
            Ok(QosCapabilities {
                cake: true,
                fq_codel: true,
                ingress: true,
                ..Default::default()
            })
        }
        async fn interface_info(&self, _interface: &str) -> Result<Vec<InterfaceInfo>, String> {
            Ok(vec![InterfaceInfo {
                name: "eth0".into(),
                link_up: true,
                ..Default::default()
            }])
        }
        async fn interface_set_mac(
            &self,
            _interface: &str,
            _mac: &str,
        ) -> Result<InterfaceResult, String> {
            Ok(InterfaceResult {
                ok: true,
                detail: "ok".into(),
                hardware_mac: Some("aa:bb:cc:dd:ee:ff".into()),
                current_mac: Some("00:11:22:33:44:55".into()),
            })
        }
        async fn interface_restore_mac(
            &self,
            _interface: &str,
        ) -> Result<InterfaceResult, String> {
            Ok(InterfaceResult {
                ok: true,
                detail: "ok".into(),
                hardware_mac: Some("aa:bb:cc:dd:ee:ff".into()),
                current_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            })
        }
        async fn tailscale_status(&self) -> Result<TailscaleStatus, String> {
            Ok(TailscaleStatus {
                installed: true,
                backend_state: "Running".into(),
                ..Default::default()
            })
        }
        async fn tailscale_up(&self, _auth_key: Option<String>) -> Result<TailscaleResult, String> {
            Ok(TailscaleResult {
                ok: true,
                detail: "up".into(),
            })
        }
        async fn tailscale_down(&self) -> Result<TailscaleResult, String> {
            Ok(TailscaleResult {
                ok: true,
                detail: "down".into(),
            })
        }
        async fn tailscale_reconnect(&self) -> Result<TailscaleResult, String> {
            Ok(TailscaleResult {
                ok: true,
                detail: "reconnected".into(),
            })
        }
        async fn tailscale_set_routes(
            &self,
            _routes: &[String],
            _exit_node: bool,
        ) -> Result<TailscaleResult, String> {
            Ok(TailscaleResult {
                ok: true,
                detail: "routes".into(),
            })
        }
    }

    #[tokio::test]
    async fn qos_intent_is_applied_and_drift_converges() {
        let exec = Arc::new(FakeExec::new());
        let manager = Arc::new(SubsystemManager::new(exec.clone()));
        manager
            .set_qos_intent(vec![fq_codel_config("eth0")])
            .await
            .unwrap();

        let snap = manager.snapshot.read().await;
        assert!(!snap.qos.applied.is_empty(), "qdisc should be applied");
        assert_eq!(snap.qos.applied[0].kind.as_deref(), Some("fq_codel"));
        assert!(!snap.qos.drift, "no drift after successful apply");
    }

    fn fq_codel_config(interface: &str) -> QosConfig {
        QosConfig {
            interface: interface.into(),
            direction: QosDirection::Egress,
            kind: QdiscKind::FqCodel,
            bandwidth_bps: None,
            latency_target_ms: None,
            overhead_bytes: None,
            ecn: true,
            wash: false,
            memory_limit_bytes: None,
            classes: vec![],
            comment: QosConfig::identity(interface),
        }
    }

    #[tokio::test]
    async fn orphan_qdiscs_are_removed() {
        let exec = Arc::new(FakeExec::new());
        exec.applied.lock().unwrap().push(AppliedQdisc {
            interface: "eth1".into(),
            index: 1,
            handle: "b51:0".into(),
            parent: "ffff:fff1".into(),
            kind: Some("fq_codel".into()),
            our_identity: true,
            stats: None,
        });
        let manager = Arc::new(SubsystemManager::new(exec.clone()));
        manager.refresh().await;

        let snap = manager.snapshot.read().await;
        assert!(
            snap.qos.applied.is_empty(),
            "orphan qdisc must be removed: {:?}",
            snap.qos.applied
        );
    }

    #[test]
    fn qos_toml_validation() {
        let entries = vec![
            QosIntentToml {
                interface: "eth0".into(),
                kind: Some("cake".into()),
                direction: Some("egress".into()),
                bandwidth_mbps: Some(100),
                latency_target_ms: Some(5),
            },
            QosIntentToml {
                interface: "".into(),
                kind: None,
                direction: None,
                bandwidth_mbps: None,
                latency_target_ms: None,
            },
        ];
        assert!(qos_intent_from_toml(&entries).is_err(), "empty interface must be rejected");

        let ok_entries = vec![QosIntentToml {
            interface: "eth0".into(),
            kind: Some("fq_codel".into()),
            direction: None,
            bandwidth_mbps: Some(50),
            latency_target_ms: None,
        }];
        let ok = qos_intent_from_toml(&ok_entries).unwrap();
        assert_eq!(ok[0].interface, "eth0");
        assert_eq!(ok[0].bandwidth_bps, Some(50_000_000));
        assert_eq!(ok[0].kind, QdiscKind::FqCodel);
    }

    #[test]
    fn snapshot_is_unified_and_serializable() {
        let snap = balansir_common::subsystems::SubsystemSnapshot::default();
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"qos\""));
        assert!(json.contains("\"tailscale\""));
        assert!(json.contains("\"interfaces\""));
    }
}
