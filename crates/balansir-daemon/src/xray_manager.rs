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

use crate::driver::ComponentDriver;
use crate::xray::{XrayConfig, XrayDriver, XrayTls, XrayTransport};

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
    pub tls: Option<XrayTls>,
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
            tls: self.tls.clone(),
            name: Some(self.name.clone()),
            socks_port: self.socks_port.unwrap_or(fallback_socks),
            http_port: self.http_port.unwrap_or(fallback_http),
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

/// Xray component manager.
pub struct XrayManager {
    snapshot: SharedSubsystemSnapshot,
    events: broadcast::Sender<SubsystemEvent>,
    endpoints: Vec<XrayEndpoint>,
    socks_port: u16,
    http_port: u16,
    #[allow(dead_code)]
    failover_threshold: u32,
    paused: Arc<AtomicBool>,
    pinned: Arc<RwLock<Option<String>>>,
    wake: Arc<Notify>,
    active: RwLock<Option<usize>>,
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
            paused: Arc::new(AtomicBool::new(false)),
            pinned: Arc::new(RwLock::new(None)),
            wake: Arc::new(Notify::new()),
            active: RwLock::new(None),
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
        })
    }

    pub fn handle(&self) -> XrayManagerHandle {
        XrayManagerHandle {
            paused: Arc::clone(&self.paused),
            pinned: Arc::clone(&self.pinned),
            wake: Arc::clone(&self.wake),
        }
    }

    fn endpoint_config(&self, idx: usize) -> XrayConfig {
        self.endpoints[idx].into_config(self.socks_port, self.http_port)
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
        let name = self.endpoints[idx].name.clone();
        let _ = self.events.send(SubsystemEvent::XrayStarted {
            profile: name.clone(),
        });
        info!("Xray: endpoint '{name}' started");
        Ok(())
    }

    async fn stop_driver(&self) {
        let mut guard = self.driver.write().await;
        if let Some(mut driver) = guard.take() {
            let _ = driver.stop().await;
            *self.active.write().await = None;
        }
    }

    async fn active_name(&self) -> Option<String> {
        let active = *self.active.read().await;
        active.map(|i| self.endpoints[i].name.clone())
    }

    fn index_of(&self, name: &str) -> Option<usize> {
        self.endpoints.iter().position(|e| e.name == name)
    }

    /// Ensure an endpoint is running. When the operator pinned a profile the
    /// loop converges to it (manual override / rotation); otherwise the
    /// preferred (priority-ordered) endpoint starts.
    async fn ensure_running(&self) -> Result<(), String> {
        let pinned_name = self.pinned.read().await.clone();
        let active = *self.active.read().await;

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
                    tls: e.tls.is_some(),
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
                    self.health_and_failover().await;
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
tls = { server_name = "us2.example.com", allow_insecure = false }
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
            if self.health.0.load(std::sync::atomic::Ordering::Relaxed) == FAKE_HEALTHY {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unhealthy { reason: 1 }
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
}
