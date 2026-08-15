//! DPI-bypass manager (Rust-native NFQUEUE engine integration).
//!
//! Loads a `BALANSIR_DPI_CONFIG` TOML (profiles/sets) and runs the
//! `balansir-b4` NFQUEUE engine, exposing status for the API/WebUI.
//!
//! The engine uses netlink (Linux-only). On other platforms the manager is a
//! harmless disabled stub so the daemon still compiles everywhere.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

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
    pub last_error: Option<String>,
}

/// Runs the DPI-bypass engine and owns its lifecycle.
pub struct DpiManager {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    inner: Option<DpiInner>,
    running: Arc<AtomicBool>,
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
                last_error: Mutex::new(None),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config_path;
            Ok(Self {
                inner: None,
                running: Arc::new(AtomicBool::new(false)),
                last_error: Mutex::new(None),
            })
        }
    }

    /// Start the engine loop (binds NFQUEUE; the loop runs on a blocking task).
    pub async fn start(&self) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            if let Some(inner) = &self.inner {
                inner.engine.run().await?;
                self.running.store(true, Ordering::SeqCst);
            }
        }
        Ok(())
    }

    pub fn stop(&self) {
        #[cfg(target_os = "linux")]
        if let Some(inner) = &self.inner {
            inner.engine.stop();
        }
        self.running.store(false, Ordering::SeqCst);
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
        let (queue_num, ports, profiles, config_path, stats) = (
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
        let (packets_seen, tls_packets, mutated, accepted) = (
            stats.packets_seen,
            stats.tls_packets,
            stats.mutated,
            stats.accepted,
        );
        #[cfg(not(target_os = "linux"))]
        let (packets_seen, tls_packets, mutated, accepted) = stats;

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
            last_error: err,
        }
    }
}

/// Default (disabled) manager.
impl Default for DpiManager {
    fn default() -> Self {
        Self {
            inner: None,
            running: Arc::new(AtomicBool::new(false)),
            last_error: Mutex::new(None),
        }
    }
}
