//! API surface trait — the seam between HTTP handlers and the daemon.
//!
//! The daemon implements this (via `ReconcilerApi`) and hands it to the API
//! server. The API crate depends only on this trait + `balansir-common`, so
//! there is no dependency cycle: `balansir-daemon` depends on `balansir-api`.

use async_trait::async_trait;
use balansir_common::{metrics::SharedMetrics, ActualState, DesiredState};
use std::sync::Arc;

/// A WebUI-facing event.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ApiEvent {
    pub timestamp: i64,
    pub event_type: String,
    pub details: String,
}

/// Live event bridge (bounded log + broadcast for SSE).
#[derive(Debug)]
pub struct ApiEventBridge {
    log: tokio::sync::RwLock<Vec<ApiEvent>>,
    sender: tokio::sync::broadcast::Sender<ApiEvent>,
    capacity: usize,
}

impl Default for ApiEventBridge {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl ApiEventBridge {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(capacity);
        Self {
            log: tokio::sync::RwLock::new(Vec::new()),
            sender,
            capacity,
        }
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<ApiEvent> {
        self.sender.subscribe()
    }

    pub async fn snapshot(&self) -> Vec<ApiEvent> {
        self.log.read().await.clone()
    }

    pub async fn record(&self, event: ApiEvent) {
        let mut log = self.log.write().await;
        log.push(event.clone());
        while log.len() > self.capacity {
            log.remove(0);
        }
        drop(log);
        let _ = self.sender.send(event);
    }
}

/// The live control-plane surface exposed to the HTTP/SSE layer.
#[async_trait]
pub trait ApiSurface: Send + Sync {
    async fn desired(&self) -> DesiredState;
    async fn actual(&self) -> ActualState;
    async fn plan(&self) -> String;
    async fn explain(&self) -> String;
    async fn fingerprint(&self) -> Option<u64>;
    async fn generation(&self) -> u64;
    async fn reload(&self, state: DesiredState) -> Result<(), String>;
    async fn reconcile(&self) -> Result<(), String>;
    async fn dns_resync(&self) -> bool;
    fn metrics(&self) -> Arc<SharedMetrics>;
    fn events(&self) -> Arc<ApiEventBridge>;

    /// Tailscale status (installed / backend state / IP / peers).
    async fn tailscale_status(&self) -> serde_json::Value;
    /// Bring Tailscale up (authentication flow).
    async fn tailscale_up(&self) -> Result<(), String>;
    /// Bring Tailscale down.
    async fn tailscale_down(&self) -> Result<(), String>;

    /// Desired QoS plans + applied interfaces (non-authoritative).
    async fn qos_status(&self) -> serde_json::Value;

    /// Per-path health reports (hysteresis-smoothed) for the WebUI.
    async fn path_health(&self) -> serde_json::Value;

    /// Xray status (installed / running).
    async fn xray_status(&self) -> serde_json::Value;
}
