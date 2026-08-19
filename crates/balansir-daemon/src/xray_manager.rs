//! Xray component manager: owns the endpoint profiles, the active Xray
//! process, failover/rotation/recovery, and publishes Xray state into the
//! unified subsystem snapshot + event bus.
//!
//! The manager is the *transport orchestration* layer. It generates a real
//! Xray config per endpoint (honoring transport/TLS/flow), starts/stops the
//! xray binary, probes the local SOCKS inbound for liveness, and — when the
//! active endpoint degrades past a threshold — fails over to the next enabled
//! endpoint. Selection is explainable: every switch records a reason.
//!
//! Two health classes (ADR-033) are kept strictly separate:
//! - **L1** (per-profile remote reachability) lives in `VpnPool` and drives
//!   selection — this manager never mutates it.
//! - **L2** (active-driver/process liveness) lives here: `l2_watchdog`
//!   supervises the *pool-driven* active runtime and applies a bounded
//!   restart/recovery guard. L2 never feeds candidate ranking.
//!
//! Security model:
//! - endpoints are validated (`XrayConfig::validate`) before any process start;
//! - configs (containing the UUID secret) are written by the driver into
//!   `/run/balansir/` with mode 0600 and wiped on stop;
//! - `pinned` (manual override) never grants anything beyond endpoint
//!   selection — failover stays enabled so an operator mistake cannot pin the
//!   network to a dead endpoint forever.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Notify, RwLock};
use tracing::{info, warn};

use balansir_common::path_health::{PathHealth, PathHealthConfig, PathSample, PathState};
use balansir_common::subsystems::{
    SharedSubsystemSnapshot, SubsystemEvent, XrayProfileView, XraySnapshot,
};
use balansir_common::HealthStatus;

/// Build the path-health tracker config for Xray endpoints. `enter_degraded`
/// is the existing `failover_threshold` (consecutive bad probes), so failover
/// timing is unchanged; hysteresis and cooldown add anti-flapping on top.
fn path_config_for(cfg: &XrayToml) -> PathHealthConfig {
    PathHealthConfig {
        enter_degraded: cfg.failover_threshold.unwrap_or(3).max(1),
        exit_degraded: 2,
        cooldown: std::time::Duration::from_secs(10),
        ..PathHealthConfig::default()
    }
}

use balansir_vpn::VpnProfile;

use crate::driver::ComponentDriver;
use crate::vpn_manager::profile_to_xray_config;
use crate::xray::{XrayConfig, XrayDriver, XraySecurity, XrayTransport};

const fn default_priority() -> i32 {
    100
}
const fn default_true() -> bool {
    true
}

/// One Xray endpoint from the profile file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayEndpoint {
    pub name: String,
    pub server: String,
    pub port: u16,
    #[serde(skip_serializing)]
    pub uuid: SecretString,
    pub flow: Option<String>,
    #[serde(default)]
    pub transport: XrayTransport,
    #[serde(default)]
    pub security: XraySecurity,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl XrayEndpoint {
    #[allow(clippy::wrong_self_convention)]
    fn into_config(&self, fallback_socks: u16, fallback_http: u16) -> XrayConfig {
        XrayConfig {
            server: self.server.clone(),
            port: self.port,
            uuid: self.uuid.clone(),
            flow: self.flow.clone(),
            transport: self.transport.clone(),
            security: self.security.clone(),
            name: Some(self.name.clone()),
            socks_port: self.socks_port.unwrap_or(fallback_socks),
            http_port: self.http_port.unwrap_or(fallback_http),
            geo_domains: Vec::new(),
        }
    }
}

/// TOML shape of the Xray component configuration (`BALANSIR_XRAY_CONFIG`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XrayToml {
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    /// Consecutive failed health probes before failover (default 3).
    pub failover_threshold: Option<u32>,
    /// Split-tunnel domains (geo-spoofing): when the VPN pool is active, only
    /// traffic to these domains is routed through the VPN outbound; all other
    /// traffic goes direct. Empty = everything proxied goes through the VPN.
    #[serde(default)]
    pub geo_domains: Vec<String>,
    #[serde(default)]
    pub profiles: Vec<XrayEndpoint>,
}

impl XrayToml {
    pub fn from_file(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        toml::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))
    }

    fn validate(&self) -> Result<(), String> {
        let mut names = std::collections::HashSet::new();
        for profile in &self.profiles {
            if profile.name.trim().is_empty() {
                return Err("xray profile name must not be empty".into());
            }
            if !names.insert(profile.name.clone()) {
                return Err(format!("duplicate xray profile name '{}'", profile.name));
            }
            profile
                .into_config(
                    self.socks_port.unwrap_or(10808),
                    self.http_port.unwrap_or(10809),
                )
                .validate()
                .map_err(|e| format!("profile '{}': {e}", profile.name))?;
        }
        Ok(())
    }
}

/// Control handle used by the API seam. It only sets intent flags; the loop
/// owns the stateful driver.
#[derive(Clone)]
pub struct XrayManagerHandle {
    paused: Arc<AtomicBool>,
    pinned: Arc<RwLock<Option<String>>>,
    wake: Arc<Notify>,
    /// External selection from the VPN pool (full profile). When set and not
    /// paused, the manager runs exactly this profile and stops its own
    /// priority-based selection — the pool is the authoritative decision.
    pool_profile: Arc<RwLock<Option<VpnProfile>>>,
    /// SOCKS5 inbound port for the Xray process (default 10808).
    socks_port: u16,
}

impl XrayManagerHandle {
    pub async fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
        self.wake.notify_one();
    }
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }
    pub async fn select(&self, profile: &str) {
        *self.pinned.write().await = Some(profile.to_string());
        self.wake.notify_one();
    }
    /// Rotate to the next enabled endpoint: pin it and wake the loop.
    pub async fn rotate_next(&self, enabled_names: Vec<String>) {
        let current = self.pinned.read().await.clone();
        let next = next_enabled(&current, &enabled_names);
        if let Some(next) = next {
            *self.pinned.write().await = Some(next);
            self.wake.notify_one();
        }
    }
    /// Apply the VPN pool's selection (full profile). `None` tells the
    /// manager to stop the proxy (no eligible profile). The pool is
    /// authoritative when set.
    pub async fn apply_pool_profile(&self, profile: Option<VpnProfile>) {
        *self.pool_profile.write().await = profile;
        self.wake.notify_one();
    }
    /// Get the SOCKS5 inbound port for the Xray process.
    pub fn socks_port(&self) -> u16 {
        self.socks_port
    }
}

/// Next enabled profile after `current` (wraps; used for manual rotation).
fn next_enabled(current: &Option<String>, enabled: &[String]) -> Option<String> {
    if enabled.is_empty() {
        return None;
    }
    let idx = current
        .as_ref()
        .and_then(|c| enabled.iter().position(|e| e == c));
    let next_idx = match idx {
        Some(i) => (i + 1) % enabled.len(),
        None => 0,
    };
    Some(enabled[next_idx].clone())
}

/// Builds the component driver for one endpoint. Injected so tests can use a
/// deterministic fake driver instead of spawning real xray processes.
type EndpointStarter = Arc<dyn Fn(XrayConfig) -> Box<dyn ComponentDriver + Send> + Send + Sync>;

/// Bounded restart/recovery guard for the active driver (ADR-033 L2).
/// Deliberately *not* a circuit breaker and *not* part of the pool health
/// model: it owns the local runtime lifecycle only and never influences
/// profile ranking/selection.
#[derive(Debug, Clone)]
pub struct L2RecoveryConfig {
    /// Startup grace window after a driver start: `Unknown` (and other
    /// non-Healthy results) are tolerated here — the driver is still coming
    /// up. After the window closes, non-Healthy is treated as evidence.
    pub grace_ms: u64,
    /// Maximum driver restarts allowed within `window_ms`. When the budget is
    /// spent, recovery is exhausted and the runtime is stopped (traffic
    /// direct).
    pub max_restarts: u32,
    /// Rolling window over which `max_restarts` is counted. Restarts that
    /// succeed push the window forward.
    pub window_ms: u64,
    /// Minimum delay between two restarts (backoff) so a wedged driver cannot
    /// burn CPU restarting in a tight loop.
    pub backoff_ms: u64,
}

impl Default for L2RecoveryConfig {
    fn default() -> Self {
        Self {
            grace_ms: 10_000,
            max_restarts: 3,
            window_ms: 60_000,
            backoff_ms: 5_000,
        }
    }
}

/// One L2 recovery decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum L2Action {
    /// Runtime healthy / within grace window: keep running, no restart.
    None,
    /// Non-Healthy observed but still within the startup grace window, or
    /// inside the backoff gap: do nothing yet.
    Grace,
    /// Bounded restart of the *same* driver (never a profile switch).
    Restart,
    /// Restart budget exhausted: stop the runtime; coordinator observes no
    /// active runtime.
    Exhaust,
}

/// The bounded restart/recovery state machine for the active driver. Pure and
/// deterministic (no IO) so the recovery semantics are unit-testable without
/// a real Xray process.
#[derive(Debug)]
struct L2Recovery {
    cfg: L2RecoveryConfig,
    /// When the current driver instance was started (grace anchor).
    started_ms: i64,
    /// Consecutive non-Healthy observations after the grace window.
    bad_count: u32,
    /// Restarts performed inside the current window.
    restarts_in_window: u32,
    /// Start of the current restart-counting window.
    window_start_ms: i64,
    /// When the last restart happened (backoff anchor).
    last_restart_ms: i64,
    /// Recovery budget spent: runtime must stay stopped until a fresh start.
    exhausted: bool,
}

impl L2Recovery {
    fn new(cfg: L2RecoveryConfig) -> Self {
        Self {
            cfg,
            started_ms: 0,
            bad_count: 0,
            restarts_in_window: 0,
            window_start_ms: 0,
            last_restart_ms: 0,
            exhausted: false,
        }
    }

    /// Record a driver start (grace anchor reset). A fresh start clears the
    /// exhaustion flag — the runtime gets a new, bounded recovery budget.
    fn on_start(&mut self, now_ms: i64) {
        self.started_ms = now_ms;
        self.bad_count = 0;
        self.restarts_in_window = 0;
        self.window_start_ms = 0;
        // Far in the past so the first recovery is never backoff-blocked.
        self.last_restart_ms = i64::MIN;
        self.exhausted = false;
    }

    /// Record an L2 recovery restart of the *same* driver: refresh the grace
    /// anchor and bad count, but keep the restart budget so bounded recovery
    /// still applies across restarts inside one window.
    fn on_restart(&mut self, now_ms: i64) {
        self.started_ms = now_ms;
        self.bad_count = 0;
        self.last_restart_ms = now_ms;
    }

    /// Observe one L2 health result and decide the recovery action.
    fn observe(&mut self, status: HealthStatus, now_ms: i64) -> L2Action {
        if self.exhausted {
            return L2Action::Exhaust;
        }
        let in_grace = now_ms.saturating_sub(self.started_ms).max(0) < self.cfg.grace_ms as i64;
        match status {
            HealthStatus::Healthy => {
                self.bad_count = 0;
                self.restarts_in_window = 0;
                self.window_start_ms = 0;
                L2Action::None
            }
            HealthStatus::Unknown => {
                if in_grace {
                    // Startup window: the driver is still coming up.
                    L2Action::Grace
                } else {
                    // Past grace, `Unknown` is evidence (stuck, never Healthy).
                    self.bad(now_ms)
                }
            }
            HealthStatus::Degraded { .. } | HealthStatus::Unhealthy { .. } => {
                if in_grace {
                    // Still booting; a transient Degraded here is expected.
                    L2Action::Grace
                } else {
                    self.bad(now_ms)
                }
            }
        }
    }

    /// Non-Healthy observation outside the grace window: recovery evidence.
    fn bad(&mut self, now_ms: i64) -> L2Action {
        self.bad_count = self.bad_count.saturating_add(1);

        // Backoff: do not restart faster than `backoff_ms` apart. A negative
        // delta (clock skew / test clock) means "at or before the restart",
        // clamp to 0 so a zero backoff still allows an immediate retry.
        if now_ms.saturating_sub(self.last_restart_ms).max(0) < self.cfg.backoff_ms as i64 {
            return L2Action::Grace;
        }

        // Rolling window: restart budget resets once the window elapses.
        if now_ms.saturating_sub(self.window_start_ms) >= self.cfg.window_ms as i64 {
            self.window_start_ms = now_ms;
            self.restarts_in_window = 0;
        }

        if self.restarts_in_window >= self.cfg.max_restarts {
            self.exhausted = true;
            return L2Action::Exhaust;
        }

        self.restarts_in_window = self.restarts_in_window.saturating_add(1);
        self.last_restart_ms = now_ms;
        L2Action::Restart
    }
}

/// Xray component manager.
pub struct XrayManager {
    snapshot: SharedSubsystemSnapshot,
    events: broadcast::Sender<SubsystemEvent>,
    endpoints: Vec<XrayEndpoint>,
    socks_port: u16,
    http_port: u16,
    #[allow(dead_code)]
    failover_threshold: u32,
    /// Split-tunnel domains (geo-spoofing): proxied traffic to these domains
    /// goes through the active outbound; everything else goes direct.
    geo_domains: Vec<String>,
    paused: Arc<AtomicBool>,
    pinned: Arc<RwLock<Option<String>>>,
    wake: Arc<Notify>,
    active: RwLock<Option<usize>>,
    /// External (VPN pool) selection: the full profile to run. Overrides
    /// priority selection; the manager is a consumer of the pool.
    pool_profile: Arc<RwLock<Option<VpnProfile>>>,
    /// Label of the currently running VPN-pool profile (no static endpoint
    /// slot; tracked here so snapshots/events stay truthful).
    pool_label: RwLock<Option<String>>,
    /// Whether the pool has taken over selection at least once. When true and
    /// the pool later selects `None`, the proxy is stopped (pool = authority).
    pool_driven: Arc<RwLock<bool>>,
    /// Unified hysteresis-aware health tracker per endpoint (mission §9).
    /// This is the source of truth for `health` / `failure_count` projections
    /// and for failover: a tracker reaching `Failing` triggers the switch.
    paths: RwLock<Vec<PathHealth>>,
    /// Best-effort connect latency per endpoint (ms), None until probed.
    latency: RwLock<Vec<Option<u64>>>,
    last_error: RwLock<Option<String>>,
    switch_reason: RwLock<Option<String>>,
    last_switch_ms: RwLock<i64>,
    driver: RwLock<Option<Box<dyn ComponentDriver + Send>>>,
    starter: EndpointStarter,
    /// L2 bounded restart/recovery guard for the active driver (ADR-033).
    /// Owns the local runtime lifecycle; never feeds selection.
    l2: RwLock<L2Recovery>,
    /// Pool-profile label whose L2 recovery was exhausted. The pool re-applying
    /// the *same* label stays stopped (no restart loop); a different selection
    /// or a fresh pool start clears the guard.
    l2_exhausted_label: RwLock<Option<String>>,
    /// Number of driver instances started since process launch (observability;
    /// used by the watchdog to report restarts truthfully).
    started_count: std::sync::atomic::AtomicU64,
}

impl XrayManager {
    fn default_starter() -> EndpointStarter {
        Arc::new(|config| Box::new(XrayDriver::new(balansir_common::DriverId::Xray, config)))
    }

    /// Build the manager from a validated Xray TOML file. All endpoints are
    /// validated eagerly; a rejected file disables the component (never a
    /// half-started runtime).
    pub fn from_toml(
        xray_cfg: &XrayToml,
        snapshot: SharedSubsystemSnapshot,
        events: broadcast::Sender<SubsystemEvent>,
    ) -> Result<Self, String> {
        Self::from_toml_with_starter(xray_cfg, snapshot, events, Self::default_starter())
    }

    /// Same as [`Self::from_toml`] but with an injectable endpoint starter
    /// (deterministic test harness — see `tests::fake_starter`).
    fn from_toml_with_starter(
        xray_cfg: &XrayToml,
        snapshot: SharedSubsystemSnapshot,
        events: broadcast::Sender<SubsystemEvent>,
        starter: EndpointStarter,
    ) -> Result<Self, String> {
        xray_cfg.validate()?;
        let n = xray_cfg.profiles.len();
        Ok(Self {
            snapshot,
            events,
            endpoints: xray_cfg.profiles.clone(),
            socks_port: xray_cfg.socks_port.unwrap_or(10808),
            http_port: xray_cfg.http_port.unwrap_or(10809),
            failover_threshold: xray_cfg.failover_threshold.unwrap_or(3).max(1),
            geo_domains: xray_cfg.geo_domains.clone(),
            paused: Arc::new(AtomicBool::new(false)),
            pinned: Arc::new(RwLock::new(None)),
            wake: Arc::new(Notify::new()),
            active: RwLock::new(None),
            pool_profile: Arc::new(RwLock::new(None)),
            pool_driven: Arc::new(RwLock::new(false)),
            pool_label: RwLock::new(None),
            paths: RwLock::new(
                xray_cfg
                    .profiles
                    .iter()
                    .map(|_| PathHealth::new(path_config_for(xray_cfg)))
                    .collect(),
            ),
            latency: RwLock::new(vec![None; n]),
            last_error: RwLock::new(None),
            switch_reason: RwLock::new(None),
            last_switch_ms: RwLock::new(0),
            driver: RwLock::new(None),
            starter,
            l2: RwLock::new(L2Recovery::new(L2RecoveryConfig::default())),
            l2_exhausted_label: RwLock::new(None),
            started_count: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn handle(&self) -> XrayManagerHandle {
        XrayManagerHandle {
            paused: Arc::clone(&self.paused),
            pinned: Arc::clone(&self.pinned),
            wake: Arc::clone(&self.wake),
            pool_profile: Arc::clone(&self.pool_profile),
            socks_port: self.socks_port,
        }
    }
    fn endpoint_config(&self, idx: usize) -> XrayConfig {
        let mut cfg = self.endpoints[idx].into_config(self.socks_port, self.http_port);
        cfg.geo_domains = self.geo_domains.clone();
        cfg
    }

    fn enabled_indices(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.endpoints.len())
            .filter(|&i| self.endpoints[i].enabled)
            .collect();
        order.sort_by_key(|&i| (self.endpoints[i].priority, i));
        order
    }

    /// Best-effort TCP connect latency to each enabled endpoint's server.
    /// Observability only: failover is driven by the local inbound liveness
    /// probe, so an endpoint outage shows as `latency_ms = None` without
    /// influencing selection. Probes run concurrently with a short timeout so
    /// N endpoints never serialize 3 s each inside the health loop (important
    /// on slow SBCs like the RPi 3B+).
    async fn probe_latencies(&self) {
        let mut probes = Vec::new();
        for (i, e) in self.endpoints.iter().enumerate() {
            if !e.enabled {
                continue;
            }
            let server = e.server.clone();
            let port = e.port;
            probes.push(tokio::spawn(async move {
                let v = measure_latency_ms(&server, port, std::time::Duration::from_secs(3)).await;
                (i, v)
            }));
        }
        let mut lat = self.latency.write().await;
        for probe in probes {
            if let Ok((i, v)) = probe.await {
                lat[i] = v;
            }
        }
    }

    fn preferred(&self) -> Option<usize> {
        self.enabled_indices().first().copied()
    }

    async fn start_endpoint(&self, idx: usize) -> Result<(), String> {
        let config = self.endpoint_config(idx);
        let mut driver = (self.starter)(config);
        driver.start().await.map_err(|e| e.to_string())?;
        *self.driver.write().await = Some(driver);
        *self.active.write().await = Some(idx);
        *self.last_switch_ms.write().await = now_ms();
        self.started_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.l2.write().await.on_start(now_ms());
        let name = self.endpoints[idx].name.clone();
        let _ = self.events.send(SubsystemEvent::XrayStarted {
            profile: name.clone(),
        });
        info!("Xray: endpoint '{name}' started");
        Ok(())
    }

    /// Start a driver from an arbitrary config (used by the VPN-pool path —
    /// auto-imported profiles have no static endpoint slot). `active` is set
    /// to `None` because these profiles are not in `self.endpoints`.
    async fn start_config(
        &self,
        config: XrayConfig,
        label: String,
        reason: String,
    ) -> Result<(), String> {
        let mut driver = (self.starter)(config);
        driver.start().await.map_err(|e| e.to_string())?;
        *self.driver.write().await = Some(driver);
        *self.active.write().await = None;
        *self.pool_label.write().await = Some(label.clone());
        *self.switch_reason.write().await = Some(reason.clone());
        *self.last_switch_ms.write().await = now_ms();
        self.started_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.l2.write().await.on_start(now_ms());
        *self.l2_exhausted_label.write().await = None;
        let _ = self.events.send(SubsystemEvent::XrayStarted {
            profile: label.clone(),
        });
        info!("Xray: pool profile '{label}' started ({reason})");
        Ok(())
    }

    /// Label of the currently running driver (pool profiles carry their own
    /// label; static endpoints report their config name).
    async fn active_label(&self) -> Option<String> {
        self.pool_label.read().await.clone()
    }

    async fn stop_driver(&self) {
        let mut guard = self.driver.write().await;
        if let Some(mut driver) = guard.take() {
            let _ = driver.stop().await;
            *self.active.write().await = None;
            *self.pool_label.write().await = None;
        }
    }

    async fn active_name(&self) -> Option<String> {
        let active = *self.active.read().await;
        match active {
            Some(i) => Some(self.endpoints[i].name.clone()),
            // Pool-driven profiles have no static endpoint slot; report the
            // running driver's label so snapshots/events stay truthful.
            None => self.active_label().await,
        }
    }

    fn index_of(&self, name: &str) -> Option<usize> {
        self.endpoints.iter().position(|e| e.name == name)
    }

    /// Ensure an endpoint is running. Priority: VPN pool selection (if set —
    /// the pool is authoritative), then operator pin, then preferred
    /// (priority-ordered) endpoint. When the pool is driving and selects "no
    /// profile", the proxy is stopped (traffic stays direct).
    async fn ensure_running(&self) -> Result<(), String> {
        let pool_profile = self.pool_profile.read().await.clone();
        let pool_driven = *self.pool_driven.read().await;
        let pinned_name = self.pinned.read().await.clone();
        let active = *self.active.read().await;

        // Pool says "run this profile": materialize its config (the profile is
        // authoritative — no static endpoint lookup needed) and converge.
        if let Some(profile) = &pool_profile {
            *self.pool_driven.write().await = true;
            let mut config = profile_to_xray_config(profile, self.socks_port, self.http_port)
                .map_err(|e| format!("vpn pool profile invalid: {e}"))?;
            config.geo_domains = self.geo_domains.clone();
            let label = format!("{} @ {}", profile.label, profile.endpoint());
            let running = self.driver.read().await.is_some();
            let running_label = self.active_label().await;
            if running && running_label.as_deref() == Some(label.as_str()) {
                return Ok(());
            }
            // L2 recovery exhaustion guard: the pool re-selecting the *same*
            // profile whose recovery budget was spent must not spin a restart
            // loop. It stays stopped (traffic direct) until the pool selects a
            // different profile or explicitly clears selection.
            if *self.l2_exhausted_label.read().await == Some(label.clone()) {
                return Ok(());
            }
            return self
                .start_config(config, label, "vpn pool selected".to_string())
                .await;
        }

        // The pool took over selection and cleared it: stop (no eligible path).
        if pool_driven {
            if self.driver.read().await.is_some() {
                self.stop_driver().await;
            }
            return Ok(());
        }

        if active.is_some() && self.driver.read().await.is_some() {
            if let Some(pinned) = &pinned_name {
                if active != self.index_of(pinned) {
                    return self.switch_to(pinned, "manual override".into()).await;
                }
            }
            return Ok(());
        }
        if let Some(pinned) = &pinned_name {
            if let Some(idx) = self.index_of(pinned) {
                return self.start_endpoint(idx).await;
            }
        }
        match self.preferred() {
            Some(idx) => self.start_endpoint(idx).await,
            None => Err("no enabled Xray endpoints configured".into()),
        }
    }

    /// Switch to an endpoint by name (manual override / rotation path).
    async fn switch_to(&self, name: &str, reason: String) -> Result<(), String> {
        let idx = self
            .index_of(name)
            .ok_or_else(|| format!("unknown xray profile '{name}'"))?;
        self.switch_to_index(idx, reason).await
    }

    /// Switch to an endpoint by index. Single implementation of the switch
    /// semantics (stop → start → reset tracker → record reason/event); both
    /// the manual and the failover paths go through here so they can never
    /// diverge.
    async fn switch_to_index(&self, idx: usize, reason: String) -> Result<(), String> {
        let prev_name = self.active_name().await;
        self.stop_driver().await;
        self.start_endpoint(idx).await?;
        self.paths.write().await[idx].reset();
        *self.switch_reason.write().await = Some(reason.clone());
        *self.last_switch_ms.write().await = now_ms();
        let to = self.endpoints[idx].name.clone();
        info!("Xray: switched {prev_name:?} -> {to} ({reason})");
        let _ = self.events.send(SubsystemEvent::XraySwitched {
            from: prev_name,
            to: to.clone(),
            reason,
        });
        Ok(())
    }

    /// Health-check the running endpoint; failover when the shared path-health
    /// tracker reaches `Failing` (hysteresis + anti-flapping cooldown). The
    /// failover reason comes from the tracker so it is always explainable.
    /// Returns the name that ended up active.
    async fn health_and_failover(&self) -> Option<String> {
        let active = *self.active.read().await;
        let idx = match active {
            Some(i) => i,
            None => return None,
        };
        let driver = self.driver.read().await;
        let status = match &*driver {
            Some(d) => d.health_check().await,
            None => return None,
        };
        drop(driver);

        let sample = match status {
            balansir_common::types::HealthStatus::Healthy => PathSample::healthy(),
            _ => PathSample::failure(),
        };

        let mut paths = self.paths.write().await;
        let label_before = paths[idx].state().label().to_string();
        let transition = paths[idx].observe(sample);
        let view = paths[idx].view();
        if paths[idx].state().label() != label_before {
            let name = self.endpoints[idx].name.clone();
            let health = view.state.clone();
            let _ = self.events.send(SubsystemEvent::XrayHealthChanged {
                profile: name,
                health,
            });
        }
        let failing = paths[idx].state() == PathState::Failing;
        let reasons = view.reasons.join("; ");
        drop(paths);

        if transition.is_some() && !failing {
            return Some(self.endpoints[idx].name.clone());
        }

        // Only a *sustained* Failing state (already hysteresis-smoothed)
        // triggers failover.
        if !failing {
            return Some(self.endpoints[idx].name.clone());
        }

        // Endpoint is failing: fail over to the next enabled endpoint.
        let enabled = self.enabled_indices();
        let next = enabled
            .iter()
            .copied()
            .find(|&i| i != idx)
            .or_else(|| enabled.first().copied());
        match next {
            Some(next) if next != idx => {
                let name = self.endpoints[idx].name.clone();
                let reason = if reasons.is_empty() {
                    format!("endpoint '{name}' failed health probes")
                } else {
                    format!("endpoint '{name}' failing: {reasons}")
                };
                let to = self.endpoints[next].name.clone();

                // Failover consumes an operator pin that pointed at the
                // failing endpoint: otherwise the next `ensure_running` pass
                // would pull straight back to the dead endpoint and the two
                // would alternate forever (the switch loop). A pin on a
                // *different* healthy endpoint is preserved.
                let pinned_now = self.pinned.read().await.clone();
                let consumed = pinned_now.as_deref() == Some(name.as_str());
                if consumed {
                    *self.pinned.write().await = None;
                    info!("Xray: consumed operator pin '{name}' after failover");
                }

                if self.switch_to_index(next, reason).await.is_err() {
                    return Some(name);
                }
                Some(to)
            }
            _ => Some(self.endpoints[idx].name.clone()),
        }
    }

    /// L2 watchdog (ADR-033): supervise the *active* runtime's local
    /// liveness and apply the bounded restart/recovery guard. Only the
    /// pool-driven driver is supervised here; static endpoints keep the
    /// legacy `health_and_failover` L2 feed. Never influences selection.
    async fn l2_watchdog(&self, now_ms: i64) {
        let status = {
            let guard = self.driver.read().await;
            match guard.as_ref() {
                Some(d) => d.health_check().await,
                None => return,
            }
        };
        // Skip the legacy static-endpoint supervision path: it already feeds
        // L2 into the shared PathHealth model (per-endpoint failover). This
        // watchdog is exclusively for pool-driven profiles.
        if !*self.pool_driven.read().await {
            return;
        }

        let action = {
            let mut l2 = self.l2.write().await;
            l2.observe(status, now_ms)
        };
        match action {
            L2Action::None | L2Action::Grace => {}
            L2Action::Restart => self.restart_active_driver().await,
            L2Action::Exhaust => self.exhaust_recovery().await,
        }
    }

    /// Bounded restart of the *same* active driver (L2 recovery). Restarts
    /// the running runtime in place — never switches to another profile — so
    /// an L2 failure cannot trigger profile rotation. On restart failure the
    /// recovery loop continues with the state machine (next pass escalates).
    async fn restart_active_driver(&self) {
        let label = self.active_label().await;
        let mut guard = self.driver.write().await;
        if let Some(driver) = guard.as_mut() {
            match driver.restart().await {
                Ok(()) => {
                    *self.last_switch_ms.write().await = now_ms();
                    // Grace anchor refresh only: keep the bounded budget
                    // so repeated failures accumulate toward exhaustion.
                    self.l2.write().await.on_restart(now_ms());
                    self.started_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    info!(
                        "Xray: L2 recovery restarted active driver{label_clause}",
                        label_clause = label
                            .as_deref()
                            .map(|l| format!(" '{l}'"))
                            .unwrap_or_default()
                    );
                    let _ = self.events.send(SubsystemEvent::XrayStarted {
                        profile: label.unwrap_or_else(|| "active".into()),
                    });
                }
                Err(e) => {
                    warn!("Xray: L2 restart failed: {e}");
                    *self.last_error.write().await = Some(format!("L2 driver restart failed: {e}"));
                }
            }
        }
    }

    /// L2 recovery budget exhausted: the active runtime is stopped (no active
    /// runtime), the coordinator observes it via the snapshot, and the pool
    /// label is guarded so a same-profile re-selection cannot spin a restart
    /// loop. Traffic goes direct — the documented honesty rule.
    async fn exhaust_recovery(&self) {
        let label = self.active_label().await.unwrap_or_else(|| "active".into());
        info!("Xray: L2 recovery exhausted for '{label}' — stopping runtime (traffic direct)");
        self.stop_driver().await;
        *self.l2_exhausted_label.write().await = Some(label.clone());
        let _ = self.events.send(SubsystemEvent::XrayError {
            detail: format!(
                "L2 recovery exhausted: active runtime '{label}' stopped (traffic direct)"
            ),
        });
    }

    async fn observe_snapshot(&self) -> XraySnapshot {
        let active = *self.active.read().await;
        let path_views = self
            .paths
            .read()
            .await
            .iter()
            .map(|p| p.view())
            .collect::<Vec<_>>();
        let latency = self.latency.read().await.clone();
        let paused = self.paused.load(Ordering::Relaxed);
        let pinned = self.pinned.read().await.clone();
        let last_error = self.last_error.read().await.clone();
        let switch_reason = self.switch_reason.read().await.clone();
        let last_switch_ms = *self.last_switch_ms.read().await;

        let profiles = self
            .endpoints
            .iter()
            .enumerate()
            .map(|(i, e)| {
                // Flatten the unified path-health view to the WebUI-compatible
                // projection. "failing" is the shared model's terminal state,
                // exposed as "Unhealthy" for UI/API compatibility.
                let path = path_views.get(i).cloned().unwrap_or_default();
                let health = match path.state.as_str() {
                    "healthy" => "Healthy".to_string(),
                    "degraded" => "Degraded".to_string(),
                    "failing" => "Unhealthy".to_string(),
                    _ => "Unknown".to_string(),
                };
                XrayProfileView {
                    name: e.name.clone(),
                    server: e.server.clone(),
                    port: e.port,
                    transport: format!("{:?}", e.transport),
                    tls: !matches!(e.security, XraySecurity::None),
                    priority: e.priority,
                    enabled: e.enabled,
                    active: active == Some(i),
                    health,
                    failure_count: path.consecutive_failures,
                    latency_ms: latency.get(i).copied().flatten(),
                    path,
                }
            })
            .collect();

        let active_name = active.map(|i| self.endpoints[i].name.clone());
        XraySnapshot {
            profiles,
            active: active_name,
            paused,
            pinned,
            last_error,
            socks_port: self.socks_port,
            http_port: self.http_port,
            switch_reason,
            last_switch_ms,
        }
    }

    /// Run the Xray component loop forever (daemon task).
    pub async fn run_loop(self, interval_secs: u64) -> ! {
        info!(
            "Xray component running ({} endpoints, interval {}s)",
            self.endpoints.len(),
            interval_secs
        );
        loop {
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {}
            }
            let paused = self.paused.load(Ordering::Relaxed);

            if paused {
                if self.driver.read().await.is_some() {
                    self.stop_driver().await;
                    let _ = self.events.send(SubsystemEvent::XrayStopped);
                }
            } else {
                match self.ensure_running().await {
                    Ok(()) => {}
                    Err(e) => {
                        warn!("Xray: {e}");
                        *self.last_error.write().await = Some(e.clone());
                        let _ = self.events.send(SubsystemEvent::XrayError { detail: e });
                    }
                }
                if self.driver.read().await.is_some() {
                    let now = now_ms();
                    if *self.pool_driven.read().await {
                        // Pool-driven runtime: supervised by the L2 watchdog
                        // (ADR-033) — bounded local recovery, never rotation.
                        self.l2_watchdog(now).await;
                    } else {
                        // Static endpoints: legacy L2→PathHealth failover feed.
                        self.health_and_failover().await;
                    }
                }
            }
            // Latency observability is independent of driver state (still useful
            // when paused so the operator can compare endpoint paths).
            self.probe_latencies().await;

            let snapshot = self.observe_snapshot().await;
            self.snapshot
                .update(move |s| {
                    s.xray = snapshot.clone();
                })
                .await;
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Best-effort TCP connect latency to `server:port` in milliseconds. Returns
/// `None` on failure or timeout (host unreachable, DNS failure, firewall).
async fn measure_latency_ms(server: &str, port: u16, timeout: std::time::Duration) -> Option<u64> {
    let addr = format!("{server}:{port}");
    let start = std::time::Instant::now();
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => Some(start.elapsed().as_millis() as u64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::{Capabilities, DriverError, DriverId, HealthStatus};

    fn sample_toml() -> XrayToml {
        toml::from_str(
            r#"
socks_port = 11080
http_port = 11081
failover_threshold = 2

[[profiles]]
name = "jp-1"
server = "jp1.example.com"
port = 443
uuid = "11111111-2222-3333-4444-555555555555"
flow = "xtls-rprx-vision"
priority = 10

[[profiles]]
name = "us-2"
server = "us2.example.com"
port = 8443
uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
transport = { WebSocket = { path = "/ws" } }
security = { tls = { server_name = "us2.example.com", pinned_peer_cert_sha256 = "e8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9" } }
priority = 20
"#,
        )
        .expect("valid toml")
    }

    #[test]
    fn parses_profiles() {
        let cfg = sample_toml();
        assert_eq!(cfg.profiles.len(), 2);
        assert_eq!(cfg.socks_port, Some(11080));
        assert_eq!(cfg.failover_threshold, Some(2));
    }

    #[test]
    fn rejects_duplicate_names() {
        let mut cfg = sample_toml();
        cfg.profiles[1].name = "jp-1".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_bad_endpoint() {
        let mut cfg = sample_toml();
        cfg.profiles[0].server = " ".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rotation_picks_next_enabled() {
        let enabled = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(next_enabled(&None, &enabled).as_deref(), Some("a"));
        assert_eq!(
            next_enabled(&Some("a".into()), &enabled).as_deref(),
            Some("b")
        );
        assert_eq!(
            next_enabled(&Some("c".into()), &enabled).as_deref(),
            Some("a")
        );
        assert_eq!(next_enabled(&Some("a".into()), &[]), None);
    }

    #[test]
    fn preferred_orders_by_priority() {
        let cfg = sample_toml();
        let manager = XrayManager::from_toml(
            &cfg,
            SharedSubsystemSnapshot::new(),
            broadcast::channel(16).0,
        )
        .expect("valid");
        let preferred = manager.preferred().expect("has endpoints");
        assert_eq!(manager.endpoints[preferred].name, "jp-1");
    }

    #[tokio::test]
    async fn snapshot_reflects_active_profile() {
        let cfg = sample_toml();
        let manager = XrayManager::from_toml(
            &cfg,
            SharedSubsystemSnapshot::new(),
            broadcast::channel(16).0,
        )
        .expect("valid");
        let snap = manager.observe_snapshot().await;
        assert_eq!(snap.profiles.len(), 2);
        assert!(snap.active.is_none());
        assert!(!snap.paused);
        assert_eq!(snap.socks_port, 11080);
        assert_eq!(snap.profiles[0].transport, "Tcp");
        assert!(snap.profiles[1].tls);
    }

    #[tokio::test]
    async fn latency_probe_measures_reachable_and_unreachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let port = addr.port();

        let measured =
            measure_latency_ms("127.0.0.1", port, std::time::Duration::from_secs(2)).await;
        assert!(measured.is_some(), "reachable endpoint must yield latency");

        // A port with no listener yields None (unreachable), not a panic.
        let unreachable =
            measure_latency_ms("127.0.0.1", 1, std::time::Duration::from_millis(200)).await;
        assert!(unreachable.is_none());
    }

    #[tokio::test]
    async fn snapshot_exposes_latency_per_profile() {
        let cfg = sample_toml();
        let manager = XrayManager::from_toml(
            &cfg,
            SharedSubsystemSnapshot::new(),
            broadcast::channel(16).0,
        )
        .expect("valid");
        *manager.latency.write().await = vec![Some(42), None];
        let snap = manager.observe_snapshot().await;
        assert_eq!(snap.profiles[0].latency_ms, Some(42));
        assert_eq!(snap.profiles[1].latency_ms, None);
    }

    /// Deterministic fake driver health signal, shared with the test so a
    /// pass can flip the endpoint's health without recreating the driver.
    #[derive(Clone)]
    struct FakeDriverHealth(std::sync::Arc<std::sync::atomic::AtomicU8>);

    const FAKE_HEALTHY: u8 = 1;
    const FAKE_UNHEALTHY: u8 = 0;
    const FAKE_DEGRADED: u8 = 2;
    const FAKE_UNKNOWN: u8 = 3;

    /// Fake endpoint driver: `start` is a no-op (no xray process), health is
    /// read from the shared signal. Exactly what the failover tests need.
    struct FakeXrayDriver {
        health: FakeDriverHealth,
        started: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ComponentDriver for FakeXrayDriver {
        fn id(&self) -> DriverId {
            DriverId::Xray
        }
        fn name(&self) -> &str {
            "fake-xray"
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities::PROXY
        }
        async fn start(&mut self) -> Result<(), DriverError> {
            self.started
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
        async fn stop(&mut self) -> Result<(), DriverError> {
            Ok(())
        }
        async fn restart(&mut self) -> Result<(), DriverError> {
            self.stop().await?;
            self.start().await
        }
        async fn health_check(&self) -> HealthStatus {
            match self.health.0.load(std::sync::atomic::Ordering::Relaxed) {
                FAKE_HEALTHY => HealthStatus::Healthy,
                FAKE_DEGRADED => HealthStatus::Degraded { reason: 2 },
                FAKE_UNKNOWN => HealthStatus::Unknown,
                _ => HealthStatus::Unhealthy { reason: 1 },
            }
        }
    }

    fn fake_starter(
        health: &FakeDriverHealth,
        started: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> EndpointStarter {
        let health = health.clone();
        let started = std::sync::Arc::clone(started);
        std::sync::Arc::new(move |_config| {
            Box::new(FakeXrayDriver {
                health: health.clone(),
                started: std::sync::Arc::clone(&started),
            })
        })
    }

    fn manager_with_fakes(
        cfg: &XrayToml,
        health: FakeDriverHealth,
        started: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> XrayManager {
        XrayManager::from_toml_with_starter(
            cfg,
            SharedSubsystemSnapshot::new(),
            broadcast::channel(16).0,
            fake_starter(&health, &started),
        )
        .expect("valid")
    }

    /// Regression: an operator pin on an endpoint that fails must be consumed
    /// by failover. Otherwise the next `ensure_running` pass pulls straight
    /// back to the dead endpoint and the two alternate forever (switch loop).
    #[tokio::test]
    async fn failover_consumes_pin_of_failed_endpoint_and_does_not_loop() {
        let cfg = sample_toml(); // failover_threshold = 2; jp-1 priority 10
        let health = FakeDriverHealth(std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
            FAKE_HEALTHY,
        )));
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let manager = manager_with_fakes(&cfg, health.clone(), started);

        // Operator pins jp-1; the loop converges to it.
        *manager.pinned.write().await = Some("jp-1".into());
        manager.ensure_running().await.expect("start pinned");
        assert_eq!(manager.active_name().await.as_deref(), Some("jp-1"));

        // jp-1 dies. Two health passes push its tracker to Failing (threshold
        // 2). The first pass degrades only; the second fails over to us-2.
        health
            .0
            .store(FAKE_UNHEALTHY, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            manager.health_and_failover().await.as_deref(),
            Some("jp-1"),
            "first bad probe must not switch yet (hysteresis)"
        );
        assert_eq!(
            manager.health_and_failover().await.as_deref(),
            Some("us-2"),
            "sustained failure must fail over"
        );

        // The consumed pin must not pull the loop back to the dead endpoint.
        assert_eq!(manager.pinned.read().await.clone(), None);
        assert_eq!(manager.active_name().await.as_deref(), Some("us-2"));
        manager.ensure_running().await.expect("stay on us-2");
        assert_eq!(
            manager.active_name().await.as_deref(),
            Some("us-2"),
            "no switch loop back to the failed pinned endpoint"
        );

        // A third pass must also stay on us-2 (no flapping).
        assert_eq!(manager.health_and_failover().await.as_deref(), Some("us-2"));
    }

    /// Failover of an *unpinned* endpoint leaves an operator pin on a healthy
    /// endpoint untouched (the pin is only consumed when it names the failing
    /// endpoint).
    #[tokio::test]
    async fn failover_preserves_pin_of_healthy_endpoint() {
        let cfg = sample_toml();
        let health = FakeDriverHealth(std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
            FAKE_HEALTHY,
        )));
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let manager = manager_with_fakes(&cfg, health.clone(), started);

        // Active = jp-1 (preferred). Operator pin = us-2 (a different,
        // healthy endpoint). jp-1 then fails → failover to us-2 must keep the
        // pin (it names the healthy target, not the failed source).
        manager.ensure_running().await.expect("start");
        *manager.pinned.write().await = Some("us-2".into());
        health
            .0
            .store(FAKE_UNHEALTHY, std::sync::atomic::Ordering::Relaxed);
        let _ = manager.health_and_failover().await; // degraded
        assert_eq!(manager.health_and_failover().await.as_deref(), Some("us-2"));
        assert_eq!(manager.pinned.read().await.clone().as_deref(), Some("us-2"));
    }

    #[tokio::test]
    async fn snapshot_flattens_unified_path_health() {
        let cfg = sample_toml(); // failover_threshold = 2
        let manager = XrayManager::from_toml(
            &cfg,
            SharedSubsystemSnapshot::new(),
            broadcast::channel(16).0,
        )
        .expect("valid");

        // Two consecutive failed probes push endpoint 0 into Failing.
        {
            let mut paths = manager.paths.write().await;
            assert!(paths[0].observe(PathSample::failure()).is_none());
            let t = paths[0].observe(PathSample::failure());
            assert_eq!(
                t,
                Some(balansir_common::path_health::PathTransition::EnteredFailing)
            );
        }

        let snap = manager.observe_snapshot().await;
        assert_eq!(
            snap.profiles[0].health, "Unhealthy",
            "model Failing maps to UI Unhealthy"
        );
        assert_eq!(snap.profiles[0].failure_count, 2);
        assert_eq!(snap.profiles[0].path.state, "failing");
        assert!(
            snap.profiles[0]
                .path
                .reasons
                .iter()
                .any(|r| r.contains("probe failures")),
            "reasons must explain the failing state: {:?}",
            snap.profiles[0].path.reasons
        );
        assert_eq!(
            snap.profiles[1].health, "Unknown",
            "untouched endpoint stays Unknown"
        );
        assert_eq!(snap.profiles[1].failure_count, 0);
    }
    /// The VPN pool is the authoritative path decision: when the pool selects
    /// a profile, the Xray manager materializes and runs it even if it is not
    /// the priority-preferred static endpoint. `None` stops the proxy.
    #[tokio::test]
    async fn pool_selection_overrides_priority() {
        let cfg = sample_toml(); // jp-1 priority 10, us-2 priority 20
        let health = FakeDriverHealth(std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
            FAKE_HEALTHY,
        )));
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let manager = manager_with_fakes(&cfg, health.clone(), started);

        // Without pool selection: jp-1 (priority 10) starts.
        manager.ensure_running().await.expect("start preferred");
        assert_eq!(manager.active_name().await.as_deref(), Some("jp-1"));

        // Pool selects a profile (the pool is authoritative). The manager
        // must run exactly that profile.
        let profile = test_profile("us2.example.com", 8443);
        manager.handle().apply_pool_profile(Some(profile)).await;
        manager.ensure_running().await.expect("converge to pool");
        assert_eq!(
            manager.active_name().await.as_deref(),
            Some("test @ us2.example.com:8443")
        );

        // Pool clears selection (no eligible profile) → stop the proxy.
        manager.handle().apply_pool_profile(None).await;
        manager.ensure_running().await.expect("stop for pool");
        assert!(manager.driver.read().await.is_none(), "proxy stopped");
    }

    /// A pool profile that cannot be materialized into an Xray config (here:
    /// a reality profile missing its public key) must fail loudly — never run
    /// the wrong thing.
    #[tokio::test]
    async fn pool_profile_missing_reality_key_fails() {
        let cfg = sample_toml();
        let health = FakeDriverHealth(std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
            FAKE_HEALTHY,
        )));
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let manager = manager_with_fakes(&cfg, health.clone(), started);

        let mut profile = test_profile("bad-reality.example.com", 443);
        profile.security = balansir_vpn::Security::Reality;
        profile.reality_pbk = None;
        manager.handle().apply_pool_profile(Some(profile)).await;
        let err = manager.ensure_running().await.expect_err("must fail");
        assert!(err.contains("missing public key"), "err: {err}");
        assert!(manager.driver.read().await.is_none(), "nothing running");
    }

    /// Set a deterministic L2 recovery config on a manager (fast grace/backoff
    /// so tests never wait real time).
    async fn set_l2_config(
        manager: &XrayManager,
        grace_ms: u64,
        max_restarts: u32,
        window_ms: u64,
        backoff_ms: u64,
    ) {
        let mut l2 = manager.l2.write().await;
        l2.cfg = L2RecoveryConfig {
            grace_ms,
            max_restarts,
            window_ms,
            backoff_ms,
        };
    }

    // ---- L2 watchdog (ADR-033) ----

    /// ADR-033: `Unknown` during the startup grace window is tolerated (no
    /// restart); once the driver reports `Healthy`, recovery converges.
    #[test]
    fn l2_unknown_within_grace_then_healthy() {
        let mut l2 = L2Recovery::new(L2RecoveryConfig {
            grace_ms: 10_000,
            max_restarts: 2,
            window_ms: 60_000,
            backoff_ms: 5_000,
        });
        l2.on_start(1_000);
        // Within grace: Unknown must not count as evidence.
        assert_eq!(l2.observe(HealthStatus::Unknown, 2_000), L2Action::Grace);
        assert_eq!(l2.bad_count, 0, "grace must not increment bad_count");
        // Still within grace, still Unknown → still no restart.
        assert_eq!(l2.observe(HealthStatus::Unknown, 3_000), L2Action::Grace);
        // Driver comes up: Healthy converges, no restart.
        assert_eq!(l2.observe(HealthStatus::Healthy, 4_000), L2Action::None);
        assert_eq!(l2.restarts_in_window, 0);
    }

    /// ADR-033: `Unknown` *after* the grace window is evidence — a driver that
    /// never reports Healthy is stuck and must be recovered.
    #[test]
    fn l2_unknown_after_grace_is_evidence() {
        let mut l2 = L2Recovery::new(L2RecoveryConfig {
            grace_ms: 10_000,
            max_restarts: 2,
            window_ms: 60_000,
            backoff_ms: 0,
        });
        l2.on_start(1_000);
        assert_eq!(l2.observe(HealthStatus::Unknown, 2_000), L2Action::Grace);
        // Past grace (t=20s): Unknown is now evidence → bounded restart.
        assert_eq!(l2.observe(HealthStatus::Unknown, 20_000), L2Action::Restart);
        assert_eq!(l2.bad_count, 1);
    }

    /// ADR-033: a single health_check failure triggers bounded recovery; a
    /// recovered driver is left running (no restart on Healthy).
    #[test]
    fn l2_single_failure_triggers_bounded_recovery() {
        let mut l2 = L2Recovery::new(L2RecoveryConfig {
            grace_ms: 0,
            max_restarts: 3,
            window_ms: 60_000,
            backoff_ms: 0,
        });
        l2.on_start(1_000);
        assert_eq!(
            l2.observe(HealthStatus::Unhealthy { reason: 1 }, 2_000),
            L2Action::Restart
        );
        assert_eq!(l2.restarts_in_window, 1);
        // Recovers: no further restart, budget resets.
        assert_eq!(l2.observe(HealthStatus::Healthy, 3_000), L2Action::None);
        assert_eq!(l2.restarts_in_window, 0);
    }

    /// ADR-033: repeated failures consume the bounded restart budget, then
    /// recovery exhausts (no infinite restart loop).
    #[test]
    fn l2_repeated_failures_hit_bounded_budget_then_exhaust() {
        let mut l2 = L2Recovery::new(L2RecoveryConfig {
            grace_ms: 0,
            max_restarts: 2,
            window_ms: 60_000,
            backoff_ms: 0,
        });
        l2.on_start(1_000);
        assert_eq!(
            l2.observe(HealthStatus::Unhealthy { reason: 1 }, 2_000),
            L2Action::Restart
        );
        assert_eq!(
            l2.observe(HealthStatus::Unhealthy { reason: 1 }, 3_000),
            L2Action::Restart
        );
        assert_eq!(
            l2.observe(HealthStatus::Unhealthy { reason: 1 }, 4_000),
            L2Action::Exhaust
        );
        assert!(l2.exhausted, "budget spent → exhausted");
        // Once exhausted, no more restarts — the guard holds.
        assert_eq!(
            l2.observe(HealthStatus::Unhealthy { reason: 1 }, 5_000),
            L2Action::Exhaust
        );
        // A fresh start resets the budget (bounded recovery per instance).
        l2.on_start(6_000);
        assert_eq!(
            l2.observe(HealthStatus::Unhealthy { reason: 1 }, 7_000),
            L2Action::Restart
        );
    }

    /// ADR-033: backoff prevents a tight restart loop — a second failure
    /// inside the backoff window must wait.
    #[test]
    fn l2_backoff_gaps_restarts() {
        let mut l2 = L2Recovery::new(L2RecoveryConfig {
            grace_ms: 0,
            max_restarts: 3,
            window_ms: 60_000,
            backoff_ms: 5_000,
        });
        l2.on_start(1_000);
        assert_eq!(
            l2.observe(HealthStatus::Degraded { reason: 2 }, 2_000),
            L2Action::Restart
        );
        // Next failure inside the 5s backoff → wait (Grace), not restart.
        assert_eq!(
            l2.observe(HealthStatus::Degraded { reason: 2 }, 3_000),
            L2Action::Grace
        );
        // After backoff elapses → restart allowed again.
        assert_eq!(
            l2.observe(HealthStatus::Degraded { reason: 2 }, 8_000),
            L2Action::Restart
        );
    }

    /// ADR-033 invariant: L2 recovery *restarts the same driver*, never
    /// switches to another profile. Healthy remote (L1 fine) + dead local Xray
    /// must produce a same-driver restart and no profile rotation.
    #[tokio::test]
    async fn l2_healthy_remote_dead_local_restarts_same_driver_no_rotation() {
        let cfg = sample_toml();
        let health = FakeDriverHealth(std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
            FAKE_HEALTHY,
        )));
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let manager = manager_with_fakes(&cfg, health.clone(), started.clone());
        set_l2_config(&manager, 0, 3, 60_000, 0).await;

        // Pool selects a profile (L1 is healthy — the pool decision is fixed).
        let profile = test_profile("us2.example.com", 8443);
        manager.handle().apply_pool_profile(Some(profile)).await;
        manager.ensure_running().await.expect("start pool profile");
        assert!(manager.driver.read().await.is_some());
        let label_before = manager.active_label().await;

        // Local Xray dies while the remote endpoint stays reachable.
        health
            .0
            .store(FAKE_UNHEALTHY, std::sync::atomic::Ordering::Relaxed);
        manager.l2_watchdog(10_000).await;

        // The SAME driver was restarted (started counter incremented), and the
        // profile did NOT rotate (same pool label, still pool-driven).
        assert_eq!(started.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(manager.active_label().await, label_before);
        assert!(*manager.pool_driven.read().await);
        assert!(manager.driver.read().await.is_some(), "still running");
    }

    /// ADR-033: L2 recovery exhausts only after the bounded budget — repeated
    /// L2 failures eventually stop the runtime (traffic direct), and the pool
    /// re-selecting the same profile stays stopped (no restart loop).
    #[tokio::test]
    async fn l2_recovery_exhaustion_stops_runtime_and_blocks_same_profile() {
        let cfg = sample_toml();
        let health = FakeDriverHealth(std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
            FAKE_HEALTHY,
        )));
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let manager = manager_with_fakes(&cfg, health.clone(), started.clone());
        set_l2_config(&manager, 0, 2, 60_000, 0).await;

        let profile = test_profile("us2.example.com", 8443);
        manager.handle().apply_pool_profile(Some(profile)).await;
        manager.ensure_running().await.expect("start");

        // Two L2 failures exhaust the budget (max_restarts=2).
        health
            .0
            .store(FAKE_UNHEALTHY, std::sync::atomic::Ordering::Relaxed);
        manager.l2_watchdog(10_000).await;
        manager.l2_watchdog(11_000).await;
        manager.l2_watchdog(12_000).await;

        // Budget exhausted: runtime stopped (no active runtime), guard set.
        assert!(manager.driver.read().await.is_none(), "runtime stopped");
        let label = "test @ us2.example.com:8443".to_string();
        assert_eq!(
            *manager.l2_exhausted_label.read().await,
            Some(label.clone())
        );

        // Pool re-applies the SAME profile: must stay stopped (no loop).
        let profile2 = test_profile("us2.example.com", 8443);
        manager.handle().apply_pool_profile(Some(profile2)).await;
        manager.ensure_running().await.expect("ensure_running ok");
        assert!(
            manager.driver.read().await.is_none(),
            "same exhausted profile must stay stopped"
        );

        // A DIFFERENT profile selection clears the guard and starts fresh.
        let other = test_profile("jp1.example.com", 443);
        manager.handle().apply_pool_profile(Some(other)).await;
        manager
            .ensure_running()
            .await
            .expect("start different profile");
        assert!(
            manager.driver.read().await.is_some(),
            "different profile starts"
        );
        assert_eq!(
            *manager.l2_exhausted_label.read().await,
            None,
            "guard cleared on different selection"
        );
    }

    /// ADR-033: L2 does not touch candidate profiles — pool selection (L1)
    /// remains the only thing that changes the running profile.
    #[tokio::test]
    async fn l2_does_not_rotate_candidates() {
        let cfg = sample_toml();
        let health = FakeDriverHealth(std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
            FAKE_HEALTHY,
        )));
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let manager = manager_with_fakes(&cfg, health.clone(), started.clone());
        set_l2_config(&manager, 0, 1, 60_000, 0).await;

        let profile = test_profile("us2.example.com", 8443);
        manager.handle().apply_pool_profile(Some(profile)).await;
        manager.ensure_running().await.expect("start");
        let label_before = manager.active_label().await;

        // Static candidate endpoints exist (jp-1, us-2) but L2 must never
        // switch to them.
        health
            .0
            .store(FAKE_UNHEALTHY, std::sync::atomic::Ordering::Relaxed);
        manager.l2_watchdog(10_000).await;
        assert_eq!(manager.active_label().await, label_before);

        // Budget exhausted (max_restarts=1) → runtime stops; still no
        // rotation to any static candidate. active_label is None because
        // nothing is running (the ADR-033 honesty rule), and no static
        // endpoint was started.
        manager.l2_watchdog(11_000).await;
        assert!(manager.driver.read().await.is_none());
        assert_eq!(
            manager.active_label().await,
            None,
            "no active runtime after exhaustion, and no static profile started"
        );
    }

    fn test_profile(server: &str, port: u16) -> VpnProfile {
        VpnProfile {
            profile_id: "test-profile".into(),
            protocol: balansir_vpn::Protocol::Vless,
            server: server.into(),
            port,
            transport: balansir_vpn::Transport::Tcp,
            security: balansir_vpn::Security::None,
            sni: None,
            reality_pbk: None,
            reality_sid: None,
            flow: Some("xtls-rprx-vision".into()),
            uuid: "11111111-2222-3333-4444-555555555555".into(),
            fingerprint: None,
            label: "test".into(),
            source: "test".into(),
            source_ts_ms: 0,
        }
    }
}
