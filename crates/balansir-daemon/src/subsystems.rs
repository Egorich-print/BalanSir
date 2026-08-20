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
use balansir_common::network::{InterfaceInfo, InterfaceResult, TailscaleResult, TailscaleStatus};
use balansir_common::qos::{AppliedQdisc, QosCapabilities, QosConfig, QosOp, QosResult};
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
    async fn interface_set_mac(
        &self,
        interface: &str,
        mac: &str,
    ) -> Result<InterfaceResult, String>;
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
        self.interface_info(interface)
            .await
            .map_err(|e| e.to_string())
    }
    async fn interface_set_mac(
        &self,
        interface: &str,
        mac: &str,
    ) -> Result<InterfaceResult, String> {
        self.interface_set_mac(interface, mac)
            .await
            .map_err(|e| e.to_string())
    }
    async fn interface_restore_mac(&self, interface: &str) -> Result<InterfaceResult, String> {
        self.interface_restore_mac(interface)
            .await
            .map_err(|e| e.to_string())
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
    b4: RwLock<Option<crate::b4_manager::B4ManagerHandle>>,
    /// DPI-bypass engine (Rust-native NFQUEUE). Attached when BALANSIR_DPI_CONFIG.
    dpi: RwLock<Option<std::sync::Arc<crate::b4_dpi::DpiManager>>>,
    #[cfg(feature = "xray")]
    xray: RwLock<Option<crate::xray_manager::XrayManagerHandle>>,
    /// VPN pool control handle (pause/refresh/rotate/pin for the API seam).
    vpn: RwLock<Option<crate::vpn_manager::VpnManagerHandle>>,
    /// Wi-Fi manager (mission §3, §4): scan/connect/status via the executor.
    wifi: RwLock<Option<crate::wifi_manager::WifiManager>>,
    /// MPTCP manager (mission §5): kernel stack state, paths, subflow health.
    mptcp: RwLock<Option<crate::mptcp_manager::MptcpManager>>,
    /// Previous CPU sample for utilization deltas.
    cpu_prev: RwLock<Option<crate::system_stats::CpuSample>>,
    /// Previous interface counters for throughput deltas: name → (rx, tx, ms).
    last_counters: RwLock<std::collections::HashMap<String, (u64, u64, u64)>>,
    /// Detected capability profile (once, on the first refresh).
    capabilities: RwLock<Option<balansir_common::subsystems::CapabilityProfile>>,
}

/// Map an executor QoS result to an error when the executor reported failure
/// over a successful IPC envelope (ok=false is still an application failure).
fn qos_result_to_result(result: balansir_common::qos::QosResult) -> Result<(), String> {
    if result.ok {
        Ok(())
    } else {
        Err(format!("{}: {}", result.op, result.detail))
    }
}
/// Does an applied qdisc satisfy a desired config? Checks identity, kind
/// and, for rate-capped kinds, the bandwidth the kernel reports. A missing
/// kernel rate (stale executor, silently degraded qdisc) counts as drift so
/// reconciliation re-applies instead of believing the old state.
fn q_matches_config(q: &AppliedQdisc, config: &QosConfig) -> bool {
    if !q.our_identity || q.interface != config.interface {
        return false;
    }
    if q.kind.as_deref() != Some(config.kind.as_str()) {
        return false;
    }
    match (config.bandwidth_bps, q.bandwidth_bps) {
        (Some(want), Some(have)) => want == have,
        (Some(_), None) => config.kind != balansir_common::qos::QdiscKind::Cake,
        (None, _) => true,
    }
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
            b4: RwLock::new(None),
            dpi: RwLock::new(None),
            #[cfg(feature = "xray")]
            xray: RwLock::new(None),
            vpn: RwLock::new(None),
            wifi: RwLock::new(None),
            mptcp: RwLock::new(None),
            cpu_prev: RwLock::new(None),
            last_counters: RwLock::new(std::collections::HashMap::new()),
            capabilities: RwLock::new(None),
        }
    }

    /// Attach the B4 controller handle (pause/resume for the API seam).
    /// Async: never `blocking_*` on a tokio lock inside the runtime (that
    /// panics with "Cannot block the current thread from within a runtime").
    pub async fn set_b4_handle(&self, handle: crate::b4_manager::B4ManagerHandle) {
        *self.b4.write().await = Some(handle);
    }

    /// Attach the DPI-bypass engine manager.
    pub async fn set_dpi(&self, dpi: std::sync::Arc<crate::b4_dpi::DpiManager>) {
        *self.dpi.write().await = Some(dpi);
    }

    /// Stop the DPI engine and remove its queue rules (graceful shutdown path).
    /// Called by the daemon before exit so no interception rule is left behind.
    pub async fn stop_dpi(&self) {
        if let Some(dpi) = self.dpi.read().await.as_ref() {
            dpi.stop().await;
        }
    }

    /// Attach the Xray manager handle (pause/select/rotate for the API seam).
    #[cfg(feature = "xray")]
    pub async fn set_xray_handle(&self, handle: crate::xray_manager::XrayManagerHandle) {
        *self.xray.write().await = Some(handle);
    }

    /// Attach the VPN pool control handle (pause/refresh/rotate/pin).
    pub async fn set_vpn_handle(&self, handle: crate::vpn_manager::VpnManagerHandle) {
        *self.vpn.write().await = Some(handle);
    }

    /// Attach the Wi-Fi manager (mission §3).
    pub async fn set_wifi_manager(&self, manager: crate::wifi_manager::WifiManager) {
        *self.wifi.write().await = Some(manager);
    }

    /// Attach the MPTCP manager (mission §5).
    pub async fn set_mptcp_manager(&self, manager: crate::mptcp_manager::MptcpManager) {
        *self.mptcp.write().await = Some(manager);
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
            Ok(mut list) => {
                // Assign roles based on NetworkConfig (if loaded).
                if let Ok(cfg) = crate::network_config::NetworkConfig::load() {
                    crate::network_config::assign_roles(&mut list, &cfg);
                }
                // WAN identity (factory/current MAC, DHCP/route observation).
                let wan = crate::wan_identity::assemble(
                    &list,
                    std::env::var("BALANSIR_WAN_INTERFACE").ok().as_deref(),
                );
                self.update_interface_rates(&list).await;
                self.snapshot
                    .update(|s| {
                        s.interfaces = list;
                        s.wan_identity = wan;
                    })
                    .await;
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

        // Wi-Fi + MPTCP subsystem views (mission §3, §5): driven by the same
        // interface snapshot; the managers forward typed ops to the executor.
        self.refresh_wifi().await;
        self.refresh_mptcp().await;

        // Capability profile (detected once, hardware-derived) ---------------
        if self.capabilities.read().await.is_none() {
            *self.capabilities.write().await = Some(crate::capability::detect());
        }
        if let Some(caps) = self.capabilities.read().await.clone() {
            self.snapshot.update(|s| s.capabilities = caps).await;
        }

        // System resources (CPU/RAM/load/uptime) ---------------------------
        let cpu_prev = *self.cpu_prev.read().await;
        if let Some((stats, cur)) = crate::system_stats::system_stats(cpu_prev.as_ref()) {
            *self.cpu_prev.write().await = Some(cur);
            self.snapshot.update(|s| s.system = stats).await;
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
                self.snapshot
                    .update(|s| {
                        s.tailscale = TailscaleSnapshot {
                            status: Some(status.clone()),
                            error: None,
                            pending_op: false,
                        }
                    })
                    .await;
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
                self.snapshot
                    .update(|s| {
                        s.tailscale = TailscaleSnapshot {
                            status: tail_prev,
                            error: Some(e.clone()),
                            pending_op: false,
                        }
                    })
                    .await;
                self.emit(SubsystemEvent::TailscaleError { detail: e });
            }
        }

        self.snapshot
            .update(|s| s.executor_unreachable = unreachable)
            .await;

        // DPI-bypass engine state (published into the same snapshot).
        if let Some(dpi) = self.dpi.read().await.as_ref() {
            let st = dpi.status();
            self.snapshot
                .update(|s| {
                    s.dpi = balansir_common::subsystems::DpiSnapshot {
                        enabled: st.enabled,
                        config_path: st.config_path,
                        queue_num: st.queue_num,
                        ports: st.ports,
                        profiles: st.profiles,
                        packets_seen: st.packets_seen,
                        tls_packets: st.tls_packets,
                        mutated: st.mutated,
                        accepted: st.accepted,
                        dropped: st.dropped,
                        errors: st.errors,
                        engine_dead: st.engine_dead,
                        last_error: st.last_error,
                        discovery: st.discovery,
                    };
                })
                .await;
        }

        if let Some(err) = qos_err {
            warn!("subsystems: QoS convergence failed: {err}");
        }

        // Unified path decision (mission §17): one authoritative answer over
        // Direct / B4 / VPN pool, derived from the already-health-tracked
        // state above. Pure projection — no second health loop.
        {
            let snap = self.snapshot.read().await;
            let b4 = snap.b4.clone();
            let vpn = snap.vpn_pool.clone();
            let dpi_active = snap.dpi.enabled && !snap.dpi.engine_dead;
            let decision = crate::path_decision::decide(&b4, &vpn, dpi_active);
            drop(snap);
            let dec = balansir_common::subsystems::PathDecision {
                overall: decision.overall,
                active_candidate: decision.active_candidate,
                reason: decision.reason,
                direct_state: decision.direct_state,
                b4_active: decision.b4_active,
                b4_ineffective: decision.b4_ineffective,
                vpn_active: decision.vpn_active,
                vpn_paused: decision.vpn_paused,
                dpi_active: decision.dpi_active,
            };
            self.snapshot.update(|s| s.path_decision = dec).await;
        }
    }

    /// Derive per-interface throughput from consecutive counter samples and
    /// publish it into the snapshot (single source of truth for the dashboard).
    async fn update_interface_rates(&self, interfaces: &[balansir_common::network::InterfaceInfo]) {
        let now_ms = crate::system_stats::now_ms();
        let prev_map = self.last_counters.read().await.clone();

        let mut rates: Vec<balansir_common::subsystems::InterfaceRate> =
            Vec::with_capacity(interfaces.len());
        for iface in interfaces {
            let (rx_bps, tx_bps) = match prev_map.get(&iface.name) {
                Some((prev_rx, prev_tx, prev_ms)) if *prev_ms < now_ms => {
                    let elapsed = std::time::Duration::from_millis(now_ms - *prev_ms);
                    (
                        crate::system_stats::rate_bps(*prev_rx, iface.rx_bytes, elapsed),
                        crate::system_stats::rate_bps(*prev_tx, iface.tx_bytes, elapsed),
                    )
                }
                _ => (0, 0),
            };
            rates.push(balansir_common::subsystems::InterfaceRate {
                interface: iface.name.clone(),
                rx_bps,
                tx_bps,
            });
        }
        rates.sort_by(|a, b| a.interface.cmp(&b.interface));

        // Record this sample as the base for the next refresh.
        let mut map = self.last_counters.write().await;
        map.clear();
        for iface in interfaces {
            map.insert(iface.name.clone(), (iface.rx_bytes, iface.tx_bytes, now_ms));
        }
        drop(map);

        self.snapshot.update(|s| s.interface_rates = rates).await;
    }

    /// Publish the Wi-Fi manager snapshot into the unified subsystem view.
    pub async fn publish_wifi(&self) {
        let wifi = self.wifi.read().await;
        if let Some(w) = wifi.as_ref() {
            let snap = w.snapshot().read().await.clone();
            self.snapshot
                .update(|s| {
                    s.wifi = balansir_common::subsystems::WifiSubsystemView {
                        interfaces: snap.interfaces,
                        networks: snap.networks,
                        states: snap.states,
                        last_error: snap.last_error,
                        busy: snap.busy,
                    };
                })
                .await;
        }
    }

    /// Publish the MPTCP manager snapshot into the unified subsystem view.
    pub async fn publish_mptcp(&self) {
        let mptcp = self.mptcp.read().await;
        if let Some(m) = mptcp.as_ref() {
            let snap = m.snapshot().read().await.clone();
            self.snapshot
                .update(|s| {
                    s.mptcp = balansir_common::subsystems::MptcpSubsystemView {
                        enabled: snap.enabled,
                        endpoints: snap.endpoints,
                        subflows: snap.subflows,
                        flow_health: snap.flow_health,
                        throughput_mbps: snap.throughput_mbps,
                        last_error: snap.last_error,
                        busy: snap.busy,
                    };
                })
                .await;
        }
    }

    /// Detect Wi-Fi interfaces and refresh the Wi-Fi manager, then publish.
    pub async fn refresh_wifi(&self) {
        let interfaces = self.snapshot.read().await.interfaces.clone();
        let wifi_interfaces = crate::wifi_manager::WifiManager::detect_wifi_interfaces(&interfaces);
        let wifi = self.wifi.read().await;
        if let Some(w) = wifi.as_ref() {
            w.refresh(&wifi_interfaces).await;
        }
        drop(wifi);
        self.publish_wifi().await;
    }

    /// Refresh the MPTCP manager and publish.
    pub async fn refresh_mptcp(&self) {
        let mptcp = self.mptcp.read().await;
        if let Some(m) = mptcp.as_ref() {
            m.refresh().await;
        }
        drop(mptcp);
        self.publish_mptcp().await;
    }

    /// Run the periodic observation loop until the task is aborted.
    pub async fn run_loop(self: Arc<Self>) {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(SUBSYSTEM_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            self.refresh().await;
        }
    }

    /// Converge QoS intent against the executor's reported qdiscs.
    async fn converge_qos(&self) -> Result<(), String> {
        let exec = &*self.exec;
        let (desired, applied, caps) =
            match (exec.qos_state("").await, exec.qos_capabilities().await) {
                (Ok(applied), Ok(caps)) => {
                    let desired = self.qos_intent.read().await.clone();
                    (desired, applied, Some(caps))
                }
                (Err(e), _) | (_, Err(e)) => {
                    self.snapshot
                        .update(|s| {
                            s.qos.last_error = Some(e.clone());
                            s.qos.drift = true;
                        })
                        .await;
                    return Err(e);
                }
            };

        // Fail loudly for unsupported kinds instead of silently degrading.
        for config in &desired {
            let supported = match config.kind {
                balansir_common::qos::QdiscKind::Cake => {
                    caps.as_ref().map(|c| c.cake).unwrap_or(false)
                }
                balansir_common::qos::QdiscKind::FqCodel => {
                    caps.as_ref().map(|c| c.fq_codel).unwrap_or(false)
                }
                balansir_common::qos::QdiscKind::Ingress => {
                    caps.as_ref().map(|c| c.ingress).unwrap_or(false)
                }
            };
            if !supported {
                let detail = format!(
                    "{} not supported on {} (kernel/module missing)",
                    config.kind.as_str(),
                    config.interface
                );
                self.snapshot
                    .update(|s| {
                        s.qos.last_error = Some(detail.clone());
                        s.qos.drift = true;
                    })
                    .await;
                self.emit(SubsystemEvent::QosError {
                    detail: detail.clone(),
                });
                return Err(detail);
            }
        }

        let mut last_error: Option<String> = None;

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
                let remove_result = match exec
                    .qos_op(&QosOp::Remove {
                        interface: q.interface.clone(),
                    })
                    .await
                {
                    Ok(r) => qos_result_to_result(r),
                    Err(e) => Err(e.to_string()),
                };
                match remove_result {
                    Ok(()) => {
                        self.emit(SubsystemEvent::QosRemoved {
                            interface: q.interface.clone(),
                        });
                    }
                    Err(e) => {
                        let detail = format!("orphan cleanup {}: {e}", q.interface);
                        self.emit(SubsystemEvent::QosError {
                            detail: detail.clone(),
                        });
                        self.snapshot
                            .update(|s| s.qos.last_error = Some(detail.clone()))
                            .await;
                        last_error = Some(detail);
                    }
                }
            }
        }

        // Apply or replace where desired and applied disagree.
        for config in &desired {
            let match_found = applied.iter().any(|q| q_matches_config(q, config));
            if !match_found {
                info!(
                    "subsystems: applying {} on {}",
                    config.kind.as_str(),
                    config.interface
                );
                let apply_result = match exec.qos_op(&QosOp::Apply(config.clone())).await {
                    Ok(r) => qos_result_to_result(r),
                    Err(e) => Err(e.to_string()),
                };
                match apply_result {
                    Ok(()) => {
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
                        warn!("subsystems: {detail}");
                        self.emit(SubsystemEvent::QosError {
                            detail: detail.clone(),
                        });
                        self.snapshot
                            .update(|s| s.qos.last_error = Some(detail.clone()))
                            .await;
                        last_error = Some(detail);
                    }
                }
            }
        }

        let applied_fresh = exec.qos_state("").await.unwrap_or(applied);
        let drift_now = desired
            .iter()
            .any(|config| !applied_fresh.iter().any(|q| q_matches_config(q, config)))
            || applied_fresh.iter().any(|q| {
                q.our_identity
                    && !desired.iter().any(|c| {
                        c.interface == q.interface
                            && c.kind.as_str() == q.kind.as_deref().unwrap_or("")
                    })
            });

        self.snapshot
            .update(|s| {
                s.qos = QosSnapshot {
                    desired: desired.clone(),
                    applied: applied_fresh,
                    capabilities: caps,
                    drift: drift_now,
                    last_error: last_error.clone(),
                };
            })
            .await;

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
        let result = self.manager.exec.interface_restore_mac(interface).await?;
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

    async fn b4_set_paused(&self, paused: bool) -> Result<(), String> {
        let handle = self.manager.b4.read().await;
        match handle.as_ref() {
            Some(handle) => {
                handle.set_paused(paused).await;
                self.manager.emit(SubsystemEvent::B4StateChanged {
                    flow: "*".to_string(),
                    state: if paused { "Paused" } else { "Running" }.to_string(),
                });
                Ok(())
            }
            None => Err("B4 engine not configured (set BALANSIR_B4_CONFIG)".to_string()),
        }
    }

    async fn b4_is_paused(&self) -> bool {
        match self.manager.b4.read().await.as_ref() {
            Some(handle) => handle.is_paused(),
            None => false,
        }
    }

    #[cfg(feature = "xray")]
    async fn xray_set_paused(&self, paused: bool) -> Result<(), String> {
        let handle = self.manager.xray.read().await;
        match handle.as_ref() {
            Some(handle) => {
                handle.set_paused(paused).await;
                Ok(())
            }
            None => Err("Xray not configured (set BALANSIR_XRAY_CONFIG)".to_string()),
        }
    }

    #[cfg(feature = "xray")]
    async fn xray_is_paused(&self) -> bool {
        match self.manager.xray.read().await.as_ref() {
            Some(handle) => handle.is_paused(),
            None => false,
        }
    }

    #[cfg(feature = "xray")]
    async fn xray_select(&self, profile: &str) -> Result<(), String> {
        let handle = self.manager.xray.read().await;
        match handle.as_ref() {
            Some(handle) => {
                handle.select(profile).await;
                Ok(())
            }
            None => Err("Xray not configured (set BALANSIR_XRAY_CONFIG)".to_string()),
        }
    }

    #[cfg(feature = "xray")]
    async fn xray_rotate(&self) -> Result<(), String> {
        let handle = self.manager.xray.read().await;
        match handle.as_ref() {
            Some(handle) => {
                let names = {
                    let snapshot = self.manager.snapshot().read().await;
                    snapshot
                        .xray
                        .profiles
                        .iter()
                        .filter(|p| p.enabled)
                        .map(|p| p.name.clone())
                        .collect()
                };
                handle.rotate_next(names).await;
                Ok(())
            }
            None => Err("Xray not configured (set BALANSIR_XRAY_CONFIG)".to_string()),
        }
    }

    #[cfg(not(feature = "xray"))]
    async fn xray_set_paused(&self, _paused: bool) -> Result<(), String> {
        Err("Xray support not compiled into this daemon".to_string())
    }
    #[cfg(not(feature = "xray"))]
    async fn xray_is_paused(&self) -> bool {
        false
    }
    #[cfg(not(feature = "xray"))]
    async fn xray_select(&self, _profile: &str) -> Result<(), String> {
        Err("Xray support not compiled into this daemon".to_string())
    }
    #[cfg(not(feature = "xray"))]
    async fn xray_rotate(&self) -> Result<(), String> {
        Err("Xray support not compiled into this daemon".to_string())
    }

    // --- VPN pool control (pool is authoritative; these drive intent) ---

    async fn vpn_set_paused(&self, paused: bool) -> Result<(), String> {
        let handle = self.manager.vpn.read().await;
        match handle.as_ref() {
            Some(handle) => {
                handle.set_paused(paused).await;
                Ok(())
            }
            None => Err("VPN pool not configured (set BALANSIR_VPN_CONFIG)".to_string()),
        }
    }

    async fn vpn_is_paused(&self) -> bool {
        self.manager
            .vpn
            .read()
            .await
            .as_ref()
            .map(|h| h.is_paused())
            .unwrap_or(false)
    }

    async fn vpn_refresh(&self) -> Result<(), String> {
        let handle = self.manager.vpn.read().await;
        match handle.as_ref() {
            Some(handle) => {
                handle.request_refresh().await;
                Ok(())
            }
            None => Err("VPN pool not configured (set BALANSIR_VPN_CONFIG)".to_string()),
        }
    }

    async fn vpn_rotate(&self) -> Result<(), String> {
        let handle = self.manager.vpn.read().await;
        match handle.as_ref() {
            Some(handle) => {
                handle.request_rotation().await;
                Ok(())
            }
            None => Err("VPN pool not configured (set BALANSIR_VPN_CONFIG)".to_string()),
        }
    }

    async fn vpn_set_pin(&self, profile_id: Option<String>) -> Result<(), String> {
        let handle = self.manager.vpn.read().await;
        match handle.as_ref() {
            Some(handle) => {
                handle.set_pin(profile_id).await;
                Ok(())
            }
            None => Err("VPN pool not configured (set BALANSIR_VPN_CONFIG)".to_string()),
        }
    }

    // --- Wi-Fi (mission §3, §4) ---

    async fn wifi_scan(
        &self,
        interface: &str,
    ) -> Result<balansir_common::network::WifiResult, String> {
        let manager = self.manager.wifi.read().await;
        match manager.as_ref() {
            Some(w) => {
                let result = w.scan(interface).await?;
                self.manager.publish_wifi().await;
                Ok(result)
            }
            None => Err("Wi-Fi manager not attached".to_string()),
        }
    }

    async fn wifi_connect(
        &self,
        interface: &str,
        ssid: &str,
        password: Option<String>,
        identity: Option<String>,
        security: Option<String>,
    ) -> Result<balansir_common::network::WifiResult, String> {
        let manager = self.manager.wifi.read().await;
        match manager.as_ref() {
            Some(w) => {
                let result = w
                    .connect(
                        interface,
                        ssid,
                        password.as_deref(),
                        identity.as_deref(),
                        security.as_deref(),
                    )
                    .await?;
                self.manager.publish_wifi().await;
                Ok(result)
            }
            None => Err("Wi-Fi manager not attached".to_string()),
        }
    }

    async fn wifi_disconnect(
        &self,
        interface: &str,
    ) -> Result<balansir_common::network::WifiResult, String> {
        let manager = self.manager.wifi.read().await;
        match manager.as_ref() {
            Some(w) => {
                let result = w.disconnect(interface).await?;
                self.manager.publish_wifi().await;
                Ok(result)
            }
            None => Err("Wi-Fi manager not attached".to_string()),
        }
    }

    // --- MPTCP (mission §5) ---

    async fn mptcp_set_enabled(
        &self,
        enabled: bool,
    ) -> Result<balansir_common::network::MptcpResult, String> {
        let manager = self.manager.mptcp.read().await;
        match manager.as_ref() {
            Some(m) => {
                let result = m.set_enabled(enabled).await?;
                self.manager.publish_mptcp().await;
                Ok(result)
            }
            None => Err("MPTCP manager not attached".to_string()),
        }
    }

    async fn mptcp_set_endpoints(
        &self,
        endpoints: Vec<(String, String)>,
    ) -> Result<balansir_common::network::MptcpResult, String> {
        let manager = self.manager.mptcp.read().await;
        match manager.as_ref() {
            Some(m) => {
                let result = m.set_endpoints(endpoints).await?;
                self.manager.publish_mptcp().await;
                Ok(result)
            }
            None => Err("MPTCP manager not attached".to_string()),
        }
    }

    async fn b4_notify_discovery(&self, domain: &str) -> Result<Option<String>, String> {
        let dpi = self.manager.dpi.read().await;
        match dpi.as_ref() {
            Some(d) => {
                let selected = d.discovery().on_blocked(domain);
                self.manager.refresh().await;
                Ok(selected)
            }
            None => Err("DPI engine not configured (set BALANSIR_DPI_CONFIG)".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::qos::QosDirection;
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
                        bandwidth_bps: None,
                    });
                    Ok(QosResult {
                        op: "apply".into(),
                        interface: config.interface.clone(),
                        ok: true,
                        detail: "applied".into(),
                    })
                }
                QosOp::Remove { interface } => {
                    self.applied
                        .lock()
                        .unwrap()
                        .retain(|q| q.interface != *interface);
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
                cake: false,
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
                previous_mac: None,
            })
        }
        async fn interface_restore_mac(&self, _interface: &str) -> Result<InterfaceResult, String> {
            Ok(InterfaceResult {
                ok: true,
                detail: "ok".into(),
                hardware_mac: Some("aa:bb:cc:dd:ee:ff".into()),
                current_mac: Some("aa:bb:cc:dd:ee:ff".into()),
                previous_mac: None,
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

    /// Executor that fails every mutating op — used to verify errors surface.
    struct FailingExec {
        inner: Arc<FakeExec>,
    }

    impl FailingExec {
        fn wrap(inner: Arc<FakeExec>) -> Arc<Self> {
            Arc::new(Self { inner })
        }
    }

    #[async_trait]
    impl SubsystemExec for FailingExec {
        async fn qos_op(&self, op: &QosOp) -> Result<QosResult, String> {
            let name = match op {
                QosOp::Apply(c) => format!("apply {}", c.interface),
                QosOp::Remove { interface } => format!("remove {interface}"),
            };
            Err(format!("{name}: netlink EPERM"))
        }
        async fn qos_state(&self, _interface: &str) -> Result<Vec<AppliedQdisc>, String> {
            self.inner.qos_state("").await
        }
        async fn qos_capabilities(&self) -> Result<QosCapabilities, String> {
            self.inner.qos_capabilities().await
        }
        async fn interface_info(&self, _interface: &str) -> Result<Vec<InterfaceInfo>, String> {
            self.inner.interface_info("").await
        }
        async fn interface_set_mac(
            &self,
            _interface: &str,
            _mac: &str,
        ) -> Result<InterfaceResult, String> {
            self.inner.interface_set_mac("", "").await
        }
        async fn interface_restore_mac(&self, _interface: &str) -> Result<InterfaceResult, String> {
            self.inner.interface_restore_mac("").await
        }
        async fn tailscale_status(&self) -> Result<TailscaleStatus, String> {
            self.inner.tailscale_status().await
        }
        async fn tailscale_up(&self, _auth_key: Option<String>) -> Result<TailscaleResult, String> {
            self.inner.tailscale_up(None).await
        }
        async fn tailscale_down(&self) -> Result<TailscaleResult, String> {
            self.inner.tailscale_down().await
        }
        async fn tailscale_reconnect(&self) -> Result<TailscaleResult, String> {
            self.inner.tailscale_reconnect().await
        }
        async fn tailscale_set_routes(
            &self,
            _routes: &[String],
            _exit_node: bool,
        ) -> Result<TailscaleResult, String> {
            self.inner.tailscale_set_routes(&[], false).await
        }
    }

    /// Executor that reports ok=false over a successful IPC envelope —
    /// the "soft failure" shape the daemon must not swallow.
    struct SoftFailingExec {
        inner: Arc<FakeExec>,
    }

    impl SoftFailingExec {
        fn wrap(inner: Arc<FakeExec>) -> Arc<Self> {
            Arc::new(Self { inner })
        }
    }

    #[async_trait]
    impl SubsystemExec for SoftFailingExec {
        async fn qos_op(&self, op: &QosOp) -> Result<QosResult, String> {
            let (name, interface) = match op {
                QosOp::Apply(c) => ("apply", c.interface.clone()),
                QosOp::Remove { interface } => ("remove", interface.clone()),
            };
            Ok(QosResult {
                op: name.into(),
                interface,
                ok: false,
                detail: "netlink EPERM".into(),
            })
        }
        async fn qos_state(&self, _interface: &str) -> Result<Vec<AppliedQdisc>, String> {
            self.inner.qos_state("").await
        }
        async fn qos_capabilities(&self) -> Result<QosCapabilities, String> {
            self.inner.qos_capabilities().await
        }
        async fn interface_info(&self, _interface: &str) -> Result<Vec<InterfaceInfo>, String> {
            self.inner.interface_info("").await
        }
        async fn interface_set_mac(
            &self,
            _interface: &str,
            _mac: &str,
        ) -> Result<InterfaceResult, String> {
            self.inner.interface_set_mac("", "").await
        }
        async fn interface_restore_mac(&self, _interface: &str) -> Result<InterfaceResult, String> {
            self.inner.interface_restore_mac("").await
        }
        async fn tailscale_status(&self) -> Result<TailscaleStatus, String> {
            self.inner.tailscale_status().await
        }
        async fn tailscale_up(&self, _auth_key: Option<String>) -> Result<TailscaleResult, String> {
            self.inner.tailscale_up(None).await
        }
        async fn tailscale_down(&self) -> Result<TailscaleResult, String> {
            self.inner.tailscale_down().await
        }
        async fn tailscale_reconnect(&self) -> Result<TailscaleResult, String> {
            self.inner.tailscale_reconnect().await
        }
        async fn tailscale_set_routes(
            &self,
            _routes: &[String],
            _exit_node: bool,
        ) -> Result<TailscaleResult, String> {
            self.inner.tailscale_set_routes(&[], false).await
        }
    }

    #[tokio::test]
    async fn soft_apply_failure_ok_false_is_not_swallowed() {
        let exec = Arc::new(FakeExec::new());
        let manager = Arc::new(SubsystemManager::new(SoftFailingExec::wrap(exec)));
        manager
            .set_qos_intent(vec![fq_codel_config("eth0")])
            .await
            .unwrap();

        let snap = manager.snapshot.read().await;
        assert!(
            snap.qos.drift,
            "drift must be true when apply reports ok=false"
        );
        let err = snap.qos.last_error.clone().expect("last_error must be set");
        assert!(err.contains("EPERM"), "actionable error expected: {err}");
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
    async fn apply_failure_surfaces_last_error_and_drift() {
        let exec = Arc::new(FakeExec::new());
        // Force apply failures: make qos_state report nothing ever applied
        // while qos_op returns an error.
        let failing = FailingExec::wrap(exec.clone());
        let manager = Arc::new(SubsystemManager::new(failing));
        manager
            .set_qos_intent(vec![fq_codel_config("eth0")])
            .await
            .unwrap();

        let snap = manager.snapshot.read().await;
        assert!(snap.qos.drift, "drift must be true when apply fails");
        let err = snap.qos.last_error.clone().expect("last_error must be set");
        assert!(err.contains("apply"), "error should name the op: {err}");
    }

    #[tokio::test]
    async fn unsupported_qdisc_kind_is_rejected() {
        let exec = Arc::new(FakeExec::new());
        let manager = Arc::new(SubsystemManager::new(exec.clone()));
        let config = QosConfig {
            interface: "eth0".into(),
            direction: QosDirection::Egress,
            kind: QdiscKind::Cake,
            bandwidth_bps: None,
            latency_target_ms: None,
            overhead_bytes: None,
            ecn: true,
            wash: false,
            memory_limit_bytes: None,
            classes: vec![],
            comment: QosConfig::identity("eth0"),
        };
        manager.set_qos_intent(vec![config]).await.unwrap_err();

        let snap = manager.snapshot.read().await;
        let err = snap.qos.last_error.clone().expect("last_error must be set");
        assert!(err.contains("not supported"), "unexpected: {err}");
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
            bandwidth_bps: None,
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
    fn qos_bandwidth_drift_detected() {
        let make_cfg = |bps: Option<u64>| QosConfig {
            interface: "eth0".into(),
            direction: QosDirection::Egress,
            kind: QdiscKind::Cake,
            bandwidth_bps: bps,
            latency_target_ms: None,
            overhead_bytes: None,
            ecn: true,
            wash: false,
            memory_limit_bytes: None,
            classes: vec![],
            comment: QosConfig::identity("eth0"),
        };
        let make_applied = |bandwidth_bps: Option<u64>| AppliedQdisc {
            interface: "eth0".into(),
            index: 1,
            handle: "b51:0".into(),
            parent: "ffff:fff1".into(),
            kind: Some("cake".into()),
            our_identity: true,
            stats: None,
            bandwidth_bps,
        };
        // Exact match: no drift.
        assert!(q_matches_config(
            &make_applied(Some(20_000_000)),
            &make_cfg(Some(20_000_000))
        ));
        // Kernel enforces a different rate than desired.
        assert!(!q_matches_config(
            &make_applied(Some(10_000_000)),
            &make_cfg(Some(20_000_000))
        ));
        // Rate-cap requested but kernel reports none (stale executor): drift.
        assert!(!q_matches_config(
            &make_applied(None),
            &make_cfg(Some(20_000_000))
        ));
        // No rate requested: kind/identity match is enough.
        assert!(q_matches_config(&make_applied(None), &make_cfg(None)));
        // Wrong interface/identity never matches.
        let foreign = AppliedQdisc {
            interface: "eth1".into(),
            ..make_applied(Some(20_000_000))
        };
        assert!(!q_matches_config(&foreign, &make_cfg(Some(20_000_000))));
        // fq_codel without a reported rate still matches (no rate requested).
        let fq = AppliedQdisc {
            kind: Some("fq_codel".into()),
            ..make_applied(None)
        };
        assert!(q_matches_config(
            &fq,
            &QosConfig {
                kind: QdiscKind::FqCodel,
                ..make_cfg(None)
            }
        ));
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
