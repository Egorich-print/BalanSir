//! DPI-bypass manager (Rust-native NFQUEUE engine integration).
//!
//! Loads a `BALANSIR_DPI_CONFIG` TOML (profiles/sets) and runs the
//! `balansir-b4` NFQUEUE engine, exposing status for the API/WebUI.
//!
//! The manager also owns the NFQUEUE *queue-rule lifecycle*: it installs the
//! nft `queue num N bypass` rules through the executor on start (idempotent,
//! no duplicates) and removes them on stop — so a stopped/crashed engine never
//! leaves a blackhole. Rules render with `bypass`, so even a leftover rule
//! with no queue instance ACCEPTS packets instead of dropping them.
//!
//! The engine uses netlink (Linux-only). On other platforms the manager is a
//! harmless disabled stub so the daemon still compiles everywhere.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(target_os = "linux")]
use balansir_common::DpiOp;

/// Live status projected to the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiStatus {
    pub enabled: bool,
    pub config_path: Option<String>,
    pub queue_num: u16,
    pub ports: Vec<u16>,
    pub profiles: Vec<String>,
    pub packets_seen: u64,
    pub tls_packets: u64,
    pub mutated: u64,
    pub accepted: u64,
    pub dropped: u64,
    pub errors: u64,
    pub engine_dead: bool,
    /// How many nft queue rules the executor reports as installed.
    pub queue_rules: u32,
    pub last_error: Option<String>,
    /// B4 Discovery view (mission §7).
    pub discovery: balansir_common::subsystems::DiscoveryView,
}

/// Runs the DPI-bypass engine and owns its lifecycle.
pub struct DpiManager {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    inner: Option<DpiInner>,
    running: Arc<AtomicBool>,
    /// Executor boundary for queue-rule install/remove. Optional: when not
    /// wired (e.g. executor unreachable) the engine still binds NFQUEUE but
    /// rule management degrades to "best effort" with an honest warning.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    executor: Option<Arc<dyn crate::reconciliation::ExecutorAdapter>>,
    last_error: Mutex<Option<String>>,
    /// B4 Discovery (mission §7): auto-selects bypass strategies for blocked
    /// domains and pushes them into the engine. Shared with the API/WebUI.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    discovery: std::sync::Arc<crate::b4_discovery::DiscoveryManager>,
}

#[cfg(target_os = "linux")]
struct DpiInner {
    engine: Arc<balansir_b4::B4Engine>,
    queue_num: u16,
    ports: Vec<u16>,
    profiles: Vec<String>,
    config_path: Option<String>,
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
struct DpiInner {
    queue_num: u16,
    ports: Vec<u16>,
    profiles: Vec<String>,
    config_path: Option<String>,
}

impl DpiManager {
    pub fn new(config_path: &str) -> Result<Self, String> {
        Self::new_with_executor(config_path, None)
    }

    /// Same as [`Self::new`] but with an executor boundary for the queue-rule
    /// lifecycle. Without it the engine still runs but queue rules are not
    /// managed by the manager (operator-managed / legacy mode).
    pub fn new_with_executor(
        config_path: &str,
        executor: Option<Arc<dyn crate::reconciliation::ExecutorAdapter>>,
    ) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            let cfg = balansir_b4::B4Config::from_file(config_path)?;
            let engine_cfg = cfg.clone().into_engine();
            let queue_num = cfg.queue_num;
            let ports = cfg.ports();
            let udp_ports = cfg.udp_ports();
            let profiles = cfg.profiles.iter().map(|p| p.name.clone()).collect();
            let sets = cfg.all_sets();
            let engine = balansir_b4::B4Engine::with_sets(
                queue_num,
                engine_cfg,
                sets,
                ports.clone(),
                udp_ports,
            );
            let engine = Arc::new(engine);
            let mut discovery = std::sync::Arc::new(crate::b4_discovery::DiscoveryManager::new());
            {
                let dm_mut =
                    std::sync::Arc::get_mut(&mut discovery).expect("fresh Arc has unique ownership");
                dm_mut.attach_engine(Arc::clone(&engine));
            }
            Ok(Self {
                inner: Some(DpiInner {
                    engine,
                    queue_num,
                    ports,
                    profiles,
                    config_path: Some(config_path.to_string()),
                }),
                running: Arc::new(AtomicBool::new(false)),
                executor,
                last_error: Mutex::new(None),
                discovery,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config_path;
            let discovery = std::sync::Arc::new(crate::b4_discovery::DiscoveryManager::new());
            Ok(Self {
                inner: None,
                running: Arc::new(AtomicBool::new(false)),
                executor,
                last_error: Mutex::new(None),
                discovery,
            })
        }
    }

    /// Start the engine loop (binds NFQUEUE; the loop runs on a blocking task)
    /// and install the queue rules through the executor.
    pub async fn start(&self) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            tracing::info!("dpi: start called, inner={}", self.inner.is_some());
            if let Some(inner) = &self.inner {
                // Fail fast on double-start: never two interception workers.
                if self.running.load(Ordering::SeqCst) {
                    return Err("DPI engine already running".into());
                }
                inner.engine.run().await?;
                self.install_queue_rules().await;
                self.running.store(true, Ordering::SeqCst);
                tracing::info!("dpi: engine.run returned Ok");
            }
        }
        Ok(())
    }

    /// Stop the engine and remove the queue rules (return traffic to the
    /// normal path — never a leftover interception rule).
    pub async fn stop(&self) {
        #[cfg(target_os = "linux")]
        {
            if let Some(inner) = &self.inner {
                inner.engine.stop();
                // Wait briefly for the interception thread to observe `running ==
                // false`; the queue unbinds on Drop when the socket closes.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            self.remove_queue_rules().await;
        }
        self.running.store(false, Ordering::SeqCst);
    }

    /// Install (idempotently) the nft queue rules for the configured ports.
    #[cfg(target_os = "linux")]
    async fn install_queue_rules(&self) {
        #[cfg(target_os = "linux")]
        {
            let Some(executor) = &self.executor else {
                tracing::warn!(
                    "DPI engine: no executor wired — queue rules not auto-installed \
                     (operator must add `queue num 0 bypass` rules)"
                );
                return;
            };
            let Some(inner) = &self.inner else { return };
            let queue_num = inner.queue_num;
            let ports = inner.ports.clone();
            match executor
                .dpi_op(&DpiOp::InstallQueue { queue_num, ports })
                .await
            {
                Ok(result) => {
                    tracing::info!(
                        rules = result.installed,
                        "DPI queue rules installed ({})",
                        result.detail
                    );
                }
                Err(e) => {
                    tracing::warn!("DPI queue rule install failed: {e}");
                    *self.last_error.lock().await = Some(format!("queue rule install: {e}"));
                }
            }
        }
    }

    /// Remove the DPI queue rules (return traffic to the normal path).
    #[cfg(target_os = "linux")]
    async fn remove_queue_rules(&self) {
        #[cfg(target_os = "linux")]
        {
            let Some(executor) = &self.executor else {
                return;
            };
            match executor.dpi_op(&DpiOp::RemoveQueue).await {
                Ok(result) => {
                    tracing::info!("DPI queue rules removed ({} installed)", result.installed);
                }
                Err(e) => {
                    tracing::warn!("DPI queue rule removal failed: {e}");
                    *self.last_error.lock().await = Some(format!("queue rule removal: {e}"));
                }
            }
        }
    }

    /// Current status for the API.
    pub fn status(&self) -> DpiStatus {
        #[cfg(target_os = "linux")]
        let (queue_num, ports, profiles, config_path, stats) = {
            if let Some(inner) = &self.inner {
                let st = inner.engine.stats();
                (
                    inner.queue_num,
                    inner.ports.clone(),
                    inner.profiles.clone(),
                    inner.config_path.clone(),
                    st,
                )
            } else {
                (0, vec![443], vec![], None, balansir_b4::B4Stats::default())
            }
        };
        #[cfg(not(target_os = "linux"))]
        let (queue_num, ports, profiles, config_path, _stats) = (
            0u16,
            vec![443u16],
            Vec::<String>::new(),
            None,
            (0u64, 0u64, 0u64, 0u64),
        );

        let err = self
            .last_error
            .try_lock()
            .map(|g| g.clone())
            .unwrap_or(None);
        #[cfg(target_os = "linux")]
        let (packets_seen, tls_packets, mutated, accepted, dropped, errors) = (
            stats.packets_seen,
            stats.tls_packets,
            stats.mutated,
            stats.accepted,
            stats.dropped,
            stats.errors,
        );
        #[cfg(not(target_os = "linux"))]
        let (packets_seen, tls_packets, mutated, accepted, dropped, errors) =
            (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);

        // Discovery state (mission §7): map into the view model.
        let dsnap = self.discovery.snapshot();
        let discovery_view = balansir_common::subsystems::DiscoveryView {
            enabled: dsnap.enabled,
            domains: dsnap
                .domains
                .into_iter()
                .map(|d| balansir_common::subsystems::DiscoveryDomainView {
                    domain: d.domain,
                    active: d.active,
                    candidates: d
                        .candidates
                        .into_iter()
                        .map(|c| balansir_common::subsystems::DiscoveryCandidateView {
                            name: c.name,
                            status: c.status,
                            quality: c.quality,
                            rejected_reason: c.rejected_reason,
                            trial_ends_ms: c.trial_ends_ms,
                        })
                        .collect(),
                    selected_ms: d.selected_ms,
                    validated_ms: d.validated_ms,
                    observed_blocked: d.observed_blocked,
                    last_event: d.last_event,
                })
                .collect(),
            last_error: dsnap.last_error,
        };

        DpiStatus {
            enabled: self.running.load(Ordering::SeqCst),
            config_path,
            queue_num,
            ports,
            profiles,
            packets_seen,
            tls_packets,
            mutated,
            accepted,
            dropped,
            errors,
            engine_dead: self.engine_dead(),
            queue_rules: 0, // populated by the executor, not the daemon
            last_error: err,
            discovery: discovery_view,
        }
    }

    /// Whether the engine thread exited unexpectedly (panic / fatal recv
    /// error). The kernel FAIL_OPEN queue flag keeps traffic flowing, but the
    /// operator must see that DPI is not actually bypassing.
    fn engine_dead(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Some(inner) = &self.inner {
                return inner.engine.is_dead();
            }
        }
        false
    }
}

/// Default (disabled) manager.
impl Default for DpiManager {
    fn default() -> Self {
        Self {
            inner: None,
            running: Arc::new(AtomicBool::new(false)),
            executor: None,
            last_error: Mutex::new(None),
            discovery: std::sync::Arc::new(crate::b4_discovery::DiscoveryManager::new()),
        }
    }
}

impl DpiManager {
    /// The Discovery manager (mission §7). The API/WebUI reads it; the policy
    /// engine calls `on_blocked` when a domain is observed blocked.
    pub fn discovery(&self) -> std::sync::Arc<crate::b4_discovery::DiscoveryManager> {
        std::sync::Arc::clone(&self.discovery)
    }

    /// Report a blocked/interfered domain to Discovery so it can select (and
    /// apply) a bypass strategy. No-op when Discovery is disabled.
    pub fn notify_blocked(&self, domain: &str) {
        self.discovery.on_blocked(domain);
    }

    /// Pause/resume the engine. Pausing stops the interception loop and removes
    /// the queue rules (traffic returns to the direct path); resuming restarts
    /// both. Honest: if the engine cannot be restarted the pause stays in
    /// effect and an error is returned.
    pub async fn set_enabled(&self, enabled: bool) -> Result<(), String> {
        if enabled {
            self.start().await
        } else {
            self.stop().await;
            Ok(())
        }
    }

    /// Whether the engine is currently running (enabled).
    pub fn is_enabled(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}
