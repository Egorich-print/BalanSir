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
            let profiles = cfg.profiles.iter().map(|p| p.name.clone()).collect();
            let engine = balansir_b4::B4Engine::new(queue_num, engine_cfg, ports.clone());
            Ok(Self {
                inner: Some(DpiInner {
                    engine: Arc::new(engine),
                    queue_num,
                    ports,
                    profiles,
                    config_path: Some(config_path.to_string()),
                }),
                running: Arc::new(AtomicBool::new(false)),
                executor,
                last_error: Mutex::new(None),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config_path;
            Ok(Self {
                inner: None,
                running: Arc::new(AtomicBool::new(false)),
                executor,
                last_error: Mutex::new(None),
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
            match executor.dpi_op(&DpiOp::InstallQueue { queue_num, ports }).await {
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
            let Some(executor) = &self.executor else { return };
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
        }
    }
}
