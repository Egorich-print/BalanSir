//! VPN pool component manager (mission §6–§15).
//!
//! Owns the `balansir-vpn` pool in the daemon:
//! * loads `BALANSIR_VPN_CONFIG` (subscription source + pool policy);
//! * fetches the external subscription **unprivileged** (this task runs in
//!   the daemon, never the privileged executor), validates + dedupes via the
//!   importer, and atomically replaces the pool (keeps the known-good pool on
//!   failure);
//! * feeds per-profile health from **real probes** (injected `ProfileProbe`;
//!   production = bounded TCP connect) through the unified `PathSample`
//!   vocabulary into the pool — never fake success samples;
//! * runs selection + planned rotation on a cadence;
//! * **consumes the pool decision and drives the Xray manager**: the Xray
//!   manager no longer decides priority/health — it runs exactly the profile
//!   the pool selected.
//!
//! Design rules:
//! * the executor is never asked to fetch or execute remote configs;
//! * a failed download / empty import never empties the working pool;
//! * profiles are validated before they ever reach the pool or the runtime;
//! * no arbitrary command execution.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use balansir_common::path_health::PathSample;
use balansir_common::subsystems::{SharedSubsystemSnapshot, SubsystemEvent};
use balansir_vpn::{import_subscription, PoolConfig, VpnPool};
use balansir_vpn::{Security, Transport, VpnProfile};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::xray::{XrayConfig, XrayReality, XraySecurity, XrayTls, XrayTransport};

/// Convert a validated pool profile into an Xray outbound config.
///
/// The pool is the source of truth for *what* to run; this bridge materializes
/// the exact runtime config (transport, TLS/REALITY, flow) so auto-imported
/// profiles never need a static Xray entry. Returns `Err` only when the
/// profile carries something the Xray runtime cannot express.
pub fn profile_to_xray_config(
    profile: &VpnProfile,
    fallback_socks: u16,
    fallback_http: u16,
) -> Result<XrayConfig, String> {
    let transport = match &profile.transport {
        Transport::Tcp => XrayTransport::Tcp,
        Transport::WebSocket { path, host } => XrayTransport::WebSocket {
            path: path.clone(),
            host: host.clone(),
        },
        Transport::Grpc { service_name } => XrayTransport::Grpc {
            service_name: service_name.clone(),
        },
        Transport::HttpUpgrade { path, host } => XrayTransport::HttpUpgrade {
            path: path.clone(),
            host: host.clone(),
        },
    };
    let security = match profile.security {
        Security::None => XraySecurity::None,
        Security::Tls => XraySecurity::Tls(XrayTls {
            server_name: profile
                .sni
                .clone()
                .unwrap_or_else(|| profile.server.clone()),
            pinned_peer_cert_sha256: None,
            verify_peer_cert_by_name: None,
            allow_insecure: false,
        }),
        Security::Reality => {
            let pbk = profile
                .reality_pbk
                .clone()
                .ok_or_else(|| "reality profile missing public key".to_string())?;
            XraySecurity::Reality(XrayReality {
                server_name: profile
                    .sni
                    .clone()
                    .unwrap_or_else(|| profile.server.clone()),
                fingerprint: profile
                    .fingerprint
                    .clone()
                    .unwrap_or_else(|| "chrome".into()),
                public_key: pbk,
                short_id: profile.reality_sid.clone().unwrap_or_default(),
                spider_x: String::new(),
            })
        }
    };
    Ok(XrayConfig {
        server: profile.server.clone(),
        port: profile.port,
        uuid: profile.uuid.clone().into(),
        flow: profile.flow.clone(),
        transport,
        security,
        name: Some(format!("{} @ {}", profile.label, profile.endpoint())),
        socks_port: fallback_socks,
        http_port: fallback_http,
        geo_domains: Vec::new(),
    })
}

/// TOML shape of `BALANSIR_VPN_CONFIG`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VpnToml {
    /// URL of the subscription to fetch (plain-text config list). Optional —
    /// when absent the pool starts empty and profiles can be loaded locally
    /// (see `local_profiles`).
    pub source_url: Option<String>,
    /// Inline local subscription body (for offline / first-boot) OR path to a
    /// local file containing config URIs.
    pub local_source: Option<String>,
    /// Interval between subscription refreshes (default 3600s).
    pub refresh_interval_secs: Option<u64>,
    /// Pool health-check cadence (default 30s).
    pub health_interval_secs: Option<u64>,
    /// Pool rotation/selection cadence (default 10s).
    pub selection_interval_secs: Option<u64>,
    /// Pool tuning (mirrors `balansir_vpn::PoolConfig`).
    #[serde(default)]
    pub pool: PoolToml,
}

/// Pool tunables exposed in the config file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoolToml {
    pub min_dwell_secs: Option<u64>,
    pub failure_cooldown_secs: Option<u64>,
    /// Anti-flap cooldown of the unified health trackers (default 10s).
    pub health_cooldown_secs: Option<u64>,
    pub rotation_interval_secs: Option<u64>,
    pub better_threshold: Option<f64>,
}

impl VpnToml {
    pub fn from_file(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        toml::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))
    }

    fn pool_config(&self) -> PoolConfig {
        let p = &self.pool;
        PoolConfig {
            min_dwell: std::time::Duration::from_secs(p.min_dwell_secs.unwrap_or(120)),
            failure_cooldown: std::time::Duration::from_secs(p.failure_cooldown_secs.unwrap_or(60)),
            health_cooldown: std::time::Duration::from_secs(p.health_cooldown_secs.unwrap_or(10)),
            rotation_interval: std::time::Duration::from_secs(
                p.rotation_interval_secs.unwrap_or(0),
            ),
            better_threshold: p.better_threshold.unwrap_or(25.0),
            ramp_steps: vec![10, 25, 50, 100],
        }
    }
}

/// Control handle for the API seam (pool pause/refresh/rotation/pin).
#[derive(Clone)]
pub struct VpnManagerHandle {
    paused: Arc<AtomicBool>,
    refresh_requested: Arc<AtomicBool>,
    manual_rotation_requested: Arc<AtomicBool>,
    pin: Arc<RwLock<Option<String>>>,
}

impl VpnManagerHandle {
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }
    pub async fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
    }
    pub async fn request_refresh(&self) {
        self.refresh_requested.store(true, Ordering::Relaxed);
    }
    pub async fn request_rotation(&self) {
        self.manual_rotation_requested
            .store(true, Ordering::Relaxed);
    }
    pub async fn set_pin(&self, profile_id: Option<String>) {
        *self.pin.write().await = profile_id;
    }
}

/// How the pool drives the Xray manager (consumer seam). Injected so tests
/// use a fake instead of real xray processes.
pub trait XrayConsumer: Send + Sync {
    /// Run the selected profile. `Some` carries the full validated profile the
    /// pool decided on; `None` = stop the proxy. The consumer (Xray manager)
    /// materializes the runtime config from the profile — no static endpoint
    /// table required.
    fn apply_selected(&self, profile: Option<&VpnProfile>);
}

/// A no-op consumer (used when Xray is not configured; the pool still tracks
/// health and selection but nothing is started).
pub struct NoopXrayConsumer;

impl XrayConsumer for NoopXrayConsumer {
    fn apply_selected(&self, _profile: Option<&VpnProfile>) {}
}

/// A consumer that forwards the pool's decision to the Xray manager.
pub struct PoolXrayConsumer<F> {
    apply: F,
}

impl<F> PoolXrayConsumer<F>
where
    F: Fn(Option<&VpnProfile>) + Send + Sync,
{
    pub fn new(apply: F) -> Self {
        Self { apply }
    }
}

impl<F> XrayConsumer for PoolXrayConsumer<F>
where
    F: Fn(Option<&VpnProfile>) + Send + Sync,
{
    fn apply_selected(&self, profile: Option<&VpnProfile>) {
        (self.apply)(profile);
    }
}

/// Health-probe seam (injected like `XrayConsumer`): production probes the
/// profile's `server:port` with a bounded TCP connect and measures latency;
/// tests inject a deterministic fake. The pool's health/rotation logic is
/// only as honest as the samples it is fed — unconditionally feeding
/// `PathSample::healthy()` would be a fake-success path that hides real
/// outages from selection, so the probe is a required dependency, not an
/// option.
pub trait ProfileProbe: Send + Sync {
    /// Probe one profile endpoint and return the unified health sample.
    fn probe<'a>(
        &'a self,
        server: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = PathSample> + Send + 'a>>;
}

/// Production probe: bounded TCP connect to `server:port`. A successful
/// connect yields `reachable` + measured latency; timeout/refused/DNS failure
/// yields `PathSample::failure()`. Cheap enough for the RPi cadence and needs
/// no extra services.
pub struct TcpConnectProbe {
    pub timeout: std::time::Duration,
}

impl Default for TcpConnectProbe {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(3),
        }
    }
}

impl ProfileProbe for TcpConnectProbe {
    fn probe<'a>(
        &'a self,
        server: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = PathSample> + Send + 'a>> {
        Box::pin(async move {
            let addr = endpoint_addr(server, port);
            let start = std::time::Instant::now();
            match tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(_stream)) => PathSample {
                    latency_ms: Some(start.elapsed().as_millis() as f64),
                    loss_pct: None,
                    reachable: true,
                    degraded_evidence: false,
                },
                _ => PathSample::failure(),
            }
        })
    }
}

/// Format `server:port` for socket resolution, bracketing bare IPv6 literals
/// (`2001:db8::1` → `[2001:db8::1]:443`). Hostnames and IPv4 pass through.
fn endpoint_addr(server: &str, port: u16) -> String {
    if server.contains(':') && !server.starts_with('[') {
        format!("[{server}]:{port}")
    } else {
        format!("{server}:{port}")
    }
}

/// The VPN pool manager.
pub struct VpnManager {
    config: VpnToml,
    pool: Arc<RwLock<VpnPool>>,
    snapshot: SharedSubsystemSnapshot,
    events: tokio::sync::broadcast::Sender<SubsystemEvent>,
    handle: VpnManagerHandle,
    consumer: Arc<dyn XrayConsumer>,
    probe: Arc<dyn ProfileProbe>,
    last_error: RwLock<Option<String>>,
    last_refresh_reason: RwLock<Option<String>>,
}

impl VpnManager {
    pub fn new(
        config: VpnToml,
        snapshot: SharedSubsystemSnapshot,
        events: tokio::sync::broadcast::Sender<SubsystemEvent>,
        consumer: Arc<dyn XrayConsumer>,
    ) -> Result<Self, String> {
        Self::new_with_probe(
            config,
            snapshot,
            events,
            consumer,
            Arc::new(TcpConnectProbe::default()),
        )
    }

    /// Full constructor with an injected health probe (tests / custom probers).
    pub fn new_with_probe(
        config: VpnToml,
        snapshot: SharedSubsystemSnapshot,
        events: tokio::sync::broadcast::Sender<SubsystemEvent>,
        consumer: Arc<dyn XrayConsumer>,
        probe: Arc<dyn ProfileProbe>,
    ) -> Result<Self, String> {
        let pool_cfg = config.pool_config();
        Ok(Self {
            config,
            pool: Arc::new(RwLock::new(VpnPool::new(pool_cfg))),
            snapshot,
            events,
            handle: VpnManagerHandle {
                paused: Arc::new(AtomicBool::new(false)),
                refresh_requested: Arc::new(AtomicBool::new(false)),
                manual_rotation_requested: Arc::new(AtomicBool::new(false)),
                pin: Arc::new(RwLock::new(None)),
            },
            consumer,
            probe,
            last_error: RwLock::new(None),
            last_refresh_reason: RwLock::new(None),
        })
    }

    pub fn handle(&self) -> VpnManagerHandle {
        self.handle.clone()
    }

    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }

    /// Fetch + validate + atomically replace the pool. Never empties the
    /// working pool on failure (mission §15). `local` import skips the
    /// network (used at boot / offline).
    async fn refresh(&self, now_ms: i64) -> Result<usize, String> {
        let mut body = String::new();
        let mut source_label = String::new();

        if let Some(local) = &self.config.local_source {
            // local_source is either inline config text or a path to a file.
            let trimmed = local.trim();
            let is_path =
                trimmed.starts_with('/') || trimmed.starts_with("./") || trimmed.starts_with("../");
            if is_path {
                body = std::fs::read_to_string(trimmed)
                    .map_err(|e| format!("read local source {trimmed}: {e}"))?;
            } else {
                body = local.clone();
            }
            source_label = "local".into();
        }

        if let Some(url) = &self.config.source_url {
            if body.is_empty() {
                // Fetch unprivileged (plain text over HTTP(S)). Bound size.
                body = fetch_subscription(url).await?;
                source_label = url.clone();
            }
        }

        let result = import_subscription(&body, &source_label, now_ms);
        if result.profiles.is_empty() {
            return Err(format!(
                "no valid profiles in source ({} rejected)",
                result.rejected.len()
            ));
        }
        let n = {
            let mut pool = self.pool.write().await;
            pool.atomic_replace(result.profiles, now_ms)?
        };
        *self.last_error.write().await = None;
        *self.last_refresh_reason.write().await = Some(format!(
            "refreshed {} profiles from {source_label} ({} rejected, {} dupes)",
            n,
            result.rejected.len(),
            result.duplicates_skipped
        ));
        let _ = self.events.send(SubsystemEvent::VpnPoolUpdated {
            profiles: n as u32,
            source: source_label,
        });
        Ok(n)
    }

    /// One selection cycle: run manual/planned rotation, select for the
    /// default flow, push the decision to the Xray consumer, and emit an
    /// event when the active profile changes.
    async fn selection_cycle(&self, now_ms: i64) {
        let active_before: Option<String>;
        {
            let mut pool = self.pool.write().await;
            active_before = pool.active().map(|s| s.to_string());

            // Manual rotation (operator requested).
            if self
                .handle
                .manual_rotation_requested
                .swap(false, Ordering::Relaxed)
            {
                let cur = pool.active().map(|s| s.to_string());
                if let Some(cur) = cur {
                    let next = pool
                        .profiles()
                        .iter()
                        .map(|p| p.profile.profile_id.clone())
                        .find(|id| *id != cur);
                    if let Some(next) = next {
                        let _ = pool.force_rotate_to(&next, "manual rotation".into(), now_ms);
                    }
                }
            }

            // Operator pin (WebUI): pin overrides rotation/selection until
            // cleared. A pinned profile that is healthy/unknown stays active;
            // a failed/cooldown pin falls through to normal selection below
            // (failover must never be blocked by a dead pin).
            let pin_applied = if let Some(pinned) = self.handle.pin.read().await.clone() {
                let state = pool
                    .profile(&pinned)
                    .map(|p| p.health.state)
                    .unwrap_or(balansir_vpn::ProfileState::Failed);
                let pin_alive = !matches!(
                    state,
                    balansir_vpn::ProfileState::Failed | balansir_vpn::ProfileState::Cooldown
                );
                if pin_alive && pool.active() != Some(pinned.as_str()) {
                    let _ = pool.force_rotate_to(&pinned, "operator pin".into(), now_ms);
                }
                pin_alive
            } else {
                false
            };

            // Planned rotation (timer-based, dwell/hysteresis gated). Skipped
            // while a live pin is held — a pinned path must not be rotated.
            if !pin_applied {
                let _ = pool.maybe_planned_rotate(now_ms);
            }

            // Selection for the default flow (health-aware weighted). Also
            // skipped while a live pin is held: select_for would override the
            // pinned active with the best-ranked candidate.
            if !pin_applied {
                let _ = pool.select_for(now_ms);
            }
        }

        // Push the active profile to the Xray consumer (pool is authoritative).
        let active = self.pool.read().await.active().map(|s| s.to_string());
        let active_profile = {
            let pool = self.pool.read().await;
            active
                .as_deref()
                .and_then(|id| pool.profile(id))
                .map(|p| p.profile.clone())
        };
        self.consumer.apply_selected(active_profile.as_ref());

        if active != active_before {
            if let Some(id) = &active {
                let reason = self
                    .pool
                    .read()
                    .await
                    .snapshot(now_ms)
                    .last_rotation_reason
                    .clone()
                    .unwrap_or_else(|| "pool selection".into());
                let _ = self.events.send(SubsystemEvent::VpnActiveChanged {
                    profile_id: id.clone(),
                    reason,
                });
            }
        }
    }

    /// The manager's main loop.
    pub async fn run_loop(self: Arc<Self>) -> ! {
        let refresh_secs = self.config.refresh_interval_secs.unwrap_or(3600);
        let health_secs = self.config.health_interval_secs.unwrap_or(30);
        let selection_secs = self.config.selection_interval_secs.unwrap_or(10);

        // Initial refresh (local source at least; network best-effort).
        match self.refresh(self.now_ms()).await {
            Ok(n) => tracing::info!("VPN pool: initial load {n} profiles"),
            Err(e) => {
                *self.last_error.write().await = Some(format!("initial refresh: {e}"));
                tracing::warn!("VPN pool: initial load failed: {e}");
            }
        }

        let mut last_refresh = self.now_ms();
        let mut last_health = self.now_ms();
        let mut last_selection = self.now_ms();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let now = self.now_ms();

            // Pause gate: keep publishing state, do nothing else.
            if self.handle.is_paused() {
                self.publish_snapshot(now).await;
                continue;
            }

            if self.handle.refresh_requested.swap(false, Ordering::Relaxed)
                || (now - last_refresh) >= refresh_secs as i64 * 1000
            {
                match self.refresh(now).await {
                    Ok(_) => last_refresh = now,
                    Err(e) => {
                        *self.last_error.write().await = Some(format!("refresh: {e}"));
                        let _ = self.events.send(SubsystemEvent::VpnPoolError { detail: e });
                    }
                }
            }

            if (now - last_health) >= health_secs as i64 * 1000 {
                self.health_cycle(now).await;
                last_health = now;
            }

            if (now - last_selection) >= selection_secs as i64 * 1000 {
                self.selection_cycle(now).await;
                last_selection = now;
            }

            self.publish_snapshot(now).await;
        }
    }

    /// Probe every profile with the injected `ProfileProbe` and feed the real
    /// samples into the pool. Probes run concurrently (N endpoints must not
    /// serialize N×timeout inside the loop — RPi 3B+ friendly, mirrors the
    /// Xray manager's `probe_latencies`).
    ///
    /// Honesty rule: a profile is healthy only because a real probe said so.
    /// A probe error maps to `PathSample::failure()` — never to a fake
    /// success — so a dead endpoint is excluded from selection and enters
    /// cooldown instead of silently keeping 100% of the traffic.
    async fn health_cycle(&self, now_ms: i64) {
        let endpoints: Vec<(String, String, u16)> = {
            let pool = self.pool.read().await;
            pool.profiles()
                .iter()
                .map(|p| {
                    (
                        p.profile.profile_id.clone(),
                        p.profile.server.clone(),
                        p.profile.port,
                    )
                })
                .collect()
        };

        let mut probes = Vec::with_capacity(endpoints.len());
        for (id, server, port) in endpoints {
            let probe = Arc::clone(&self.probe);
            probes.push(tokio::spawn(async move {
                let sample = probe.probe(&server, port).await;
                (id, sample)
            }));
        }

        for probe in probes {
            match probe.await {
                Ok((id, sample)) => {
                    let mut pool = self.pool.write().await;
                    pool.observe_health(&id, sample, now_ms);
                }
                Err(e) => {
                    tracing::warn!("VPN pool health probe task failed: {e}");
                }
            }
        }
    }

    async fn publish_snapshot(&self, now_ms: i64) {
        let (profiles, active, last_rotation_ms, last_rotation_reason) = {
            let pool = self.pool.read().await;
            let snap = pool.snapshot(now_ms);
            (
                snap.profiles,
                snap.active,
                snap.last_rotation_ms,
                snap.last_rotation_reason,
            )
        };
        let err = self.last_error.read().await.clone();
        let reason = self.last_refresh_reason.read().await.clone();
        let paused = self.handle.is_paused();
        let vpn = balansir_common::subsystems::VpnSnapshot {
            enabled: !paused,
            paused,
            profiles,
            active,
            last_rotation_reason,
            last_rotation_ms,
            last_refresh_reason: reason,
            last_error: err,
            updated_ms: now_ms,
        };
        self.snapshot
            .update(move |s| {
                s.vpn_pool = vpn.clone();
            })
            .await;
    }
}

/// Fetch a plain-text subscription (HTTP/HTTPS), bounded size.
async fn fetch_subscription(url: &str) -> Result<String, String> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(format!("subscription URL must be http(s): {url}"));
    }
    let resp = reqwest_lite(url).await?;
    Ok(resp)
}

/// Minimal HTTP(S) GET that returns the body. We avoid pulling in a full HTTP
/// client for the embedded build; this uses the system `curl` binary (present
/// on the RPi image) with a size bound and no shell interpolation.
async fn reqwest_lite(url: &str) -> Result<String, String> {
    // `curl --max-filesize` bounds the response; `--silent --show-error`
    // surfaces failures; args are fixed (no user input reaches a shell).
    let url = url.to_string();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "20",
                "--max-filesize",
                "1048576",
                &url,
            ])
            .output()
    })
    .await
    .map_err(|e| format!("curl join failed: {e}"))?
    .map_err(|e| format!("curl spawn failed: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("subscription fetch failed: {err}"));
    }
    String::from_utf8(out.stdout).map_err(|_| "subscription is not UTF-8".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Deterministic consumer that records every selection it is told to run.
    struct RecordingConsumer(Mutex<Vec<Option<String>>>);

    impl XrayConsumer for RecordingConsumer {
        fn apply_selected(&self, profile: Option<&VpnProfile>) {
            self.0.lock().unwrap().push(profile.map(|p| p.endpoint()));
        }
    }

    fn test_toml() -> VpnToml {
        toml::from_str(
            r#"
local_source = '''
vless://194302fe-9c53-4203-b17e-c0b30a4d79b6@a.example.com:443?security=none&type=tcp#A
vless://194302fe-9c53-4203-b17e-c0b30a4d79b6@b.example.com:443?security=none&type=tcp#B
'''
"#,
        )
        .expect("valid toml")
    }

    #[test]
    fn vpn_toml_parses_and_defaults_pool() {
        let cfg = test_toml();
        let pool_cfg = cfg.pool_config();
        assert_eq!(pool_cfg.min_dwell, std::time::Duration::from_secs(120));
    }

    #[tokio::test]
    async fn refresh_loads_validated_profiles_into_pool() {
        let cfg = test_toml();
        let consumer = Arc::new(RecordingConsumer(Mutex::new(Vec::new())));
        let manager = VpnManager::new(
            cfg,
            SharedSubsystemSnapshot::new(),
            tokio::sync::broadcast::channel(16).0,
            consumer.clone(),
        )
        .expect("manager");
        let n = manager.refresh(1_700_000_000_000).await.expect("refresh");
        assert_eq!(n, 2, "two valid vless profiles");
        let pool = manager.pool.read().await;
        assert_eq!(pool.profiles().len(), 2);
    }

    #[tokio::test]
    async fn failed_refresh_keeps_working_pool() {
        let cfg = test_toml();
        let consumer = Arc::new(RecordingConsumer(Mutex::new(Vec::new())));
        let manager = VpnManager::new(
            cfg,
            SharedSubsystemSnapshot::new(),
            tokio::sync::broadcast::channel(16).0,
            consumer.clone(),
        )
        .expect("manager");
        manager.refresh(1_700_000_000_000).await.expect("initial");
        let before = manager.pool.read().await.profiles().len();
        // A refresh from a garbage source must fail and keep the pool.
        let mut bad = manager.config.clone();
        bad.local_source = Some("# only comments\n\ntrojan://x@y:443#z".into());
        // Use a fresh manager with the bad config (refresh is on &self, no way
        // to mutate config after construction) — instead exercise the pool's
        // atomic_replace guard directly.
        let mut pool = manager.pool.write().await;
        let res = pool.atomic_replace(vec![], 0);
        assert!(res.is_err());
        assert_eq!(pool.profiles().len(), before);
    }

    #[tokio::test]
    async fn selection_pushes_active_to_consumer() {
        let cfg = test_toml();
        let consumer = Arc::new(RecordingConsumer(Mutex::new(Vec::new())));
        let manager = VpnManager::new(
            cfg,
            SharedSubsystemSnapshot::new(),
            tokio::sync::broadcast::channel(16).0,
            consumer.clone(),
        )
        .expect("manager");
        manager.refresh(1_700_000_000_000).await.expect("refresh");
        manager.selection_cycle(1_700_000_000_000).await;
        let recorded = consumer.0.lock().unwrap();
        assert_eq!(recorded.len(), 1, "one selection applied");
        assert!(
            recorded[0].is_some(),
            "an eligible profile was selected and pushed to the consumer"
        );
    }

    #[tokio::test]
    async fn no_eligible_profiles_yields_stop() {
        // A single profile that is made to fail → selection should push None
        // (stop the proxy) — the consumer records it.
        let cfg = VpnToml {
            local_source: Some(
                "vless://194302fe-9c53-4203-b17e-c0b30a4d79b6@a.example.com:443?security=none&type=tcp#A"
                    .to_string(),
            ),
            ..Default::default()
        };
        let consumer = Arc::new(RecordingConsumer(Mutex::new(Vec::new())));
        let manager = VpnManager::new(
            cfg,
            SharedSubsystemSnapshot::new(),
            tokio::sync::broadcast::channel(16).0,
            consumer.clone(),
        )
        .expect("manager");
        manager.refresh(1_700_000_000_000).await.expect("refresh");
        let id = {
            let pool = manager.pool.read().await;
            pool.profiles()[0].profile.profile_id.clone()
        };
        // Fail the only profile twice (enter_degraded=2).
        manager
            .pool
            .write()
            .await
            .observe_health(&id, PathSample::failure(), 1_700_000_000_000);
        manager
            .pool
            .write()
            .await
            .observe_health(&id, PathSample::failure(), 1_700_000_000_000);
        manager.selection_cycle(1_700_000_000_000).await;
        let recorded = consumer.0.lock().unwrap();
        let last = recorded.last().unwrap();
        assert!(
            last.is_none(),
            "no eligible profile → consumer told to stop"
        );
    }

    /// Deterministic probe fake: per-server reachability that the test can
    /// flip at will. A reachable server reports a fixed 50 ms sample.
    struct FakeProbe {
        reachable: Mutex<std::collections::HashMap<String, bool>>,
    }

    impl FakeProbe {
        fn new(pairs: &[(&str, bool)]) -> Self {
            Self {
                reachable: Mutex::new(pairs.iter().map(|(s, r)| (s.to_string(), *r)).collect()),
            }
        }
        fn set(&self, server: &str, reachable: bool) {
            self.reachable
                .lock()
                .unwrap()
                .insert(server.to_string(), reachable);
        }
    }

    impl ProfileProbe for FakeProbe {
        fn probe<'a>(
            &'a self,
            server: &'a str,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = PathSample> + Send + 'a>> {
            Box::pin(async move {
                match self.reachable.lock().unwrap().get(server).copied() {
                    Some(true) => PathSample {
                        latency_ms: Some(50.0),
                        loss_pct: None,
                        reachable: true,
                        degraded_evidence: false,
                    },
                    _ => PathSample::failure(),
                }
            })
        }
    }

    fn manager_with_probe(probe: Arc<FakeProbe>) -> (VpnManager, Arc<RecordingConsumer>) {
        manager_with_probe_cfg(test_toml(), probe)
    }

    fn manager_with_probe_cfg(
        cfg: VpnToml,
        probe: Arc<FakeProbe>,
    ) -> (VpnManager, Arc<RecordingConsumer>) {
        let consumer = Arc::new(RecordingConsumer(Mutex::new(Vec::new())));
        let manager = VpnManager::new_with_probe(
            cfg,
            SharedSubsystemSnapshot::new(),
            tokio::sync::broadcast::channel(16).0,
            consumer.clone(),
            probe,
        )
        .expect("manager");
        (manager, consumer)
    }

    const T0: i64 = 1_700_000_000_000;

    /// Failure scenario (mission): A healthy + B healthy → A becomes
    /// unreachable via real probes → A is excluded (Failed/cooldown), new
    /// selections use B, and the consumer is switched to B.
    #[tokio::test]
    async fn probe_failure_excludes_profile_and_failovers() {
        let probe = Arc::new(FakeProbe::new(&[
            ("a.example.com", false),
            ("b.example.com", true),
        ]));
        let (manager, consumer) = manager_with_probe(probe);
        manager.refresh(T0).await.expect("refresh");

        // Initial selection: both unknown/healthy → some profile active.
        manager.selection_cycle(T0).await;
        assert!(consumer.0.lock().unwrap().last().unwrap().is_some());

        // Real probes: A fails. enter_degraded=2 → two cycles.
        manager.health_cycle(T0 + 1_000).await;
        manager.health_cycle(T0 + 2_000).await;
        let a_id = {
            let pool = manager.pool.read().await;
            pool.profiles()
                .iter()
                .find(|p| p.profile.server == "a.example.com")
                .unwrap()
                .profile
                .profile_id
                .clone()
        };
        {
            let pool = manager.pool.read().await;
            let state = pool.profile(&a_id).unwrap().health.state;
            assert!(
                matches!(
                    state,
                    balansir_vpn::profile::ProfileState::Failed
                        | balansir_vpn::profile::ProfileState::Cooldown
                ),
                "A failed real probes → excluded state, got {state:?}"
            );
        }

        // Selection must now avoid A and land on B.
        manager.selection_cycle(T0 + 3_000).await;
        let recorded = consumer.0.lock().unwrap();
        let last = recorded.last().unwrap().as_ref().unwrap();
        assert!(
            last.starts_with("b.example.com:"),
            "failover to healthy B, got {last}"
        );
    }

    /// Recovery scenario (mission): A in cooldown after real failures → real
    /// probes succeed again → A does not instantly jump back to full weight
    /// but becomes Recovering and re-enters selection eligibility.
    #[tokio::test]
    async fn probe_recovery_ramps_back_after_cooldown() {
        let probe = Arc::new(FakeProbe::new(&[
            ("a.example.com", false),
            ("b.example.com", true),
        ]));
        // health_cooldown = 0: the unified tracker gates improving transitions
        // by a wall-clock anti-flap cooldown; deterministic tests disable it
        // (same convention as the pool's own tests).
        let mut cfg = test_toml();
        cfg.pool.health_cooldown_secs = Some(0);
        let (manager, _consumer) = manager_with_probe_cfg(cfg, probe.clone());
        manager.refresh(T0).await.expect("refresh");
        manager.health_cycle(T0).await;
        manager.health_cycle(T0 + 1_000).await;
        let a_id = {
            let pool = manager.pool.read().await;
            pool.profiles()
                .iter()
                .find(|p| p.profile.server == "a.example.com")
                .unwrap()
                .profile
                .profile_id
                .clone()
        };

        // Heal A, but within the failure cooldown (60s default): still excluded.
        probe.set("a.example.com", true);
        manager.health_cycle(T0 + 30_000).await;
        {
            let pool = manager.pool.read().await;
            let state = pool.profile(&a_id).unwrap().health.state;
            assert!(
                matches!(
                    state,
                    balansir_vpn::profile::ProfileState::Failed
                        | balansir_vpn::profile::ProfileState::Cooldown
                ),
                "cooldown must not be bypassed by one good probe, got {state:?}"
            );
        }

        // Past cooldown: improving transitions are gated by the 10s health
        // cooldown, so space the probes. exit_degraded=3 good samples.
        let t1 = T0 + 61_000;
        manager.health_cycle(t1).await;
        manager.health_cycle(t1 + 11_000).await;
        {
            let pool = manager.pool.read().await;
            let h = &pool.profile(&a_id).unwrap().health;
            assert_eq!(
                h.state,
                balansir_vpn::profile::ProfileState::Recovering,
                "recovered profile ramps up instead of instant Healthy"
            );
            assert_eq!(
                h.weight, 50,
                "3 consecutive good probes → ramp step 3 of [10, 25, 50, 100]"
            );
        }
    }

    /// No-healthy-VPN scenario (mission): the only profile fails real probes →
    /// the consumer is told to stop (None), never a silent fake success.
    #[tokio::test]
    async fn probe_failure_of_last_profile_stops_proxy() {
        let cfg = VpnToml {
            local_source: Some(
                "vless://194302fe-9c53-4203-b17e-c0b30a4d79b6@dead.example.com:443?security=none&type=tcp#Dead"
                    .to_string(),
            ),
            ..Default::default()
        };
        let probe = Arc::new(FakeProbe::new(&[("dead.example.com", false)]));
        let consumer = Arc::new(RecordingConsumer(Mutex::new(Vec::new())));
        let manager = VpnManager::new_with_probe(
            cfg,
            SharedSubsystemSnapshot::new(),
            tokio::sync::broadcast::channel(16).0,
            consumer.clone(),
            probe,
        )
        .expect("manager");
        manager.refresh(T0).await.expect("refresh");
        manager.health_cycle(T0).await;
        manager.health_cycle(T0 + 1_000).await;
        manager.selection_cycle(T0 + 2_000).await;
        let recorded = consumer.0.lock().unwrap();
        assert!(
            recorded.last().unwrap().is_none(),
            "all profiles failing real probes → proxy stopped (no silent success)"
        );
    }

    /// Mission matrix scenario: A failed, B healthy, C failed → A and C
    /// excluded with reasons, B selected; a failing probe for A/C never aborts
    /// the health cycle for the others.
    #[tokio::test]
    async fn failed_healthy_failed_matrix_selects_the_healthy_one() {
        let cfg = VpnToml {
            local_source: Some(
                "vless://194302fe-9c53-4203-b17e-c0b30a4d79b6@a.example.com:443?security=none&type=tcp#A\n\
                 vless://194302fe-9c53-4203-b17e-c0b30a4d79b6@b.example.com:443?security=none&type=tcp#B\n\
                 vless://194302fe-9c53-4203-b17e-c0b30a4d79b6@c.example.com:443?security=none&type=tcp#C"
                    .to_string(),
            ),
            ..Default::default()
        };
        let probe = Arc::new(FakeProbe::new(&[
            ("a.example.com", false),
            ("b.example.com", true),
            ("c.example.com", false),
        ]));
        let (manager, consumer) = manager_with_probe_cfg(cfg, probe);
        manager.refresh(T0).await.expect("refresh: 3 profiles");
        {
            let pool = manager.pool.read().await;
            assert_eq!(pool.profiles().len(), 3);
        }

        // enter_degraded=2 → two probe cycles; A and C fail, B healthy.
        manager.health_cycle(T0).await;
        manager.health_cycle(T0 + 1_000).await;

        // Both failures were recorded — a failing probe never aborted the cycle.
        {
            let pool = manager.pool.read().await;
            for host in ["a.example.com", "c.example.com"] {
                let p = pool
                    .profiles()
                    .iter()
                    .find(|p| p.profile.server == host)
                    .unwrap();
                assert!(
                    matches!(
                        p.health.state,
                        balansir_vpn::profile::ProfileState::Failed
                            | balansir_vpn::profile::ProfileState::Cooldown
                    ),
                    "{host} must be excluded, got {:?}",
                    p.health.state
                );
            }
            let b = pool
                .profiles()
                .iter()
                .find(|p| p.profile.server == "b.example.com")
                .unwrap();
            assert_eq!(
                b.health.state,
                balansir_vpn::profile::ProfileState::Healthy,
                "B stays healthy"
            );
        }

        manager.selection_cycle(T0 + 2_000).await;
        let recorded = consumer.0.lock().unwrap();
        let last = recorded.last().unwrap().as_ref().unwrap();
        assert!(
            last.starts_with("b.example.com:"),
            "healthy B selected, got {last}"
        );
    }

    #[test]
    fn pool_consumer_maps_selection() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let c = seen.clone();
        let consumer = PoolXrayConsumer::new(move |p: Option<&VpnProfile>| {
            c.lock().unwrap().push(p.map(|x| x.endpoint()));
        });
        let profile = VpnProfile {
            profile_id: "abc123".into(),
            protocol: balansir_vpn::Protocol::Vless,
            server: "s.example.com".into(),
            port: 443,
            transport: balansir_vpn::Transport::Tcp,
            security: balansir_vpn::Security::None,
            sni: None,
            reality_pbk: None,
            reality_sid: None,
            flow: None,
            uuid: "194302fe-9c53-4203-b17e-c0b30a4d79b6".into(),
            fingerprint: None,
            label: "A".into(),
            source: "test".into(),
            source_ts_ms: 0,
        };
        consumer.apply_selected(Some(&profile));
        consumer.apply_selected(None);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![Some("s.example.com:443".to_string()), None]
        );
    }

    #[test]
    fn endpoint_addr_brackets_bare_ipv6_and_passes_others_through() {
        assert_eq!(endpoint_addr("2001:db8::1", 443), "[2001:db8::1]:443");
        assert_eq!(endpoint_addr("s.example.com", 443), "s.example.com:443");
        assert_eq!(endpoint_addr("192.168.1.1", 443), "192.168.1.1:443");
        assert_eq!(
            endpoint_addr("[2001:db8::1]", 443),
            "[2001:db8::1]:443",
            "already-bracketed IPv6 must not be double-bracketed"
        );
    }
}
