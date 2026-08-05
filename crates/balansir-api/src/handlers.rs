use axum::{
    extract::State,
    http::StatusCode,
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    Json,
};
use balansir_common::DesiredState;
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::ApiState;

/// Reconciler handle (simplified)
pub struct ReconcilerHandle {
    desired: RwLock<DesiredState>,
    event_log: RwLock<Vec<EventEntry>>,
    reconcile_count: AtomicU64,
    event_sender: tokio::sync::broadcast::Sender<EventEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EventEntry {
    pub timestamp: i64,
    pub event_type: String,
    pub details: String,
}

impl Default for ReconcilerHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl ReconcilerHandle {
    pub fn new() -> Self {
        let (event_sender, _) = tokio::sync::broadcast::channel(100);
        Self {
            desired: RwLock::new(DesiredState::default()),
            event_log: RwLock::new(Vec::new()),
            reconcile_count: AtomicU64::new(0),
            event_sender,
        }
    }

    pub async fn get_desired(&self) -> DesiredState {
        self.desired.read().await.clone()
    }

    pub async fn set_desired(&self, state: DesiredState) {
        *self.desired.write().await = state;
    }

    pub async fn add_event(&self, event_type: &str, details: &str) {
        let entry = EventEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            event_type: event_type.to_string(),
            details: details.to_string(),
        };

        // Add to log
        let mut log = self.event_log.write().await;
        log.push(entry.clone());
        if log.len() > 100 {
            log.remove(0);
        }

        // Broadcast to SSE subscribers
        let _ = self.event_sender.send(entry);
    }

    pub async fn get_events(&self) -> Vec<EventEntry> {
        self.event_log.read().await.clone()
    }

    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<EventEntry> {
        self.event_sender.subscribe()
    }

    pub async fn trigger_reconcile(&self) -> u64 {
        let count = self.reconcile_count.fetch_add(1, Ordering::Relaxed);
        self.add_event("reconcile", "manual trigger").await;
        count + 1
    }
}

/// Health check handler
pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "version": "0.1.0",
        "uptime_seconds": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }))
}

/// Metrics handler
pub async fn metrics(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let body = state.metrics.encode_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}

/// Get desired state
pub async fn get_desired(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let desired = if let Some(ref reconciler) = state.reconciler {
        reconciler.get_desired().await
    } else {
        DesiredState::default()
    };

    let rules: Vec<serde_json::Value> = desired
        .rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "action": format!("{:?}", r.action),
                "priority": r.priority,
            })
        })
        .collect();

    Json(serde_json::json!({
        "rules": rules,
        "rule_count": desired.rules.len(),
    }))
}

/// Set desired state
pub async fn set_desired(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    if let Some(ref reconciler) = state.reconciler {
        reconciler.add_event("desired_updated", "via API").await;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "message": "Use POST with JSON body"})),
    )
}

/// Get drift status
pub async fn get_drift(State(_state): State<Arc<ApiState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "drift_count": 0,
        "items": [],
        "message": "State is consistent"
    }))
}

/// Trigger manual reconciliation
pub async fn trigger_reconcile(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    if let Some(ref reconciler) = state.reconciler {
        let count = reconciler.trigger_reconcile().await;
        state.metrics.get().record_reconciliation();

        Json(serde_json::json!({
            "ok": true,
            "reconcile_id": count,
        }))
    } else {
        Json(serde_json::json!({
            "ok": false,
            "error": "Reconciler not available",
        }))
    }
}

/// Get events
pub async fn get_events(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let events = if let Some(ref reconciler) = state.reconciler {
        reconciler.get_events().await
    } else {
        Vec::new()
    };

    Json(serde_json::json!({
        "events": events,
        "count": events.len(),
    }))
}

/// SSE event stream handler
pub async fn events_stream(
    State(state): State<Arc<ApiState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let receiver = if let Some(ref reconciler) = state.reconciler {
        reconciler.subscribe_events()
    } else {
        let (_, rx) = tokio::sync::broadcast::channel(1);
        rx
    };

    let stream = BroadcastStream::new(receiver)
        .filter_map(|result| result.ok())
        .map(|entry| {
            let data = serde_json::to_string(&entry).unwrap_or_default();
            Ok(Event::default().data(data))
        });

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(30))
            .text("ping"),
    )
}

/// Ready check (Kubernetes-style)
pub async fn ready() -> impl IntoResponse {
    // TODO: Check if all components are initialized
    Json(serde_json::json!({
        "ready": true,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

/// Liveness check (Kubernetes-style)
pub async fn live() -> impl IntoResponse {
    Json(serde_json::json!({
        "alive": true,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

/// Version information
pub async fn version() -> impl IntoResponse {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": env!("CARGO_PKG_NAME"),
    }))
}

/// Build information
pub async fn build_info() -> impl IntoResponse {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "rust_version": option_env!("RUSTC_VERSION").unwrap_or("unknown"),
        "target": option_env!("TARGET").unwrap_or("unknown"),
        "build_time": option_env!("BUILD_TIME").unwrap_or("unknown"),
        "git_hash": option_env!("GIT_HASH").unwrap_or("unknown"),
    }))
}

/// Get actual state
pub async fn get_actual(State(_state): State<Arc<ApiState>>) -> impl IntoResponse {
    // TODO: Get actual state from reconciler
    Json(serde_json::json!({
        "rules": [],
        "rule_count": 0,
    }))
}

/// Get combined state (desired + actual + drift)
pub async fn get_state(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let desired = if let Some(ref reconciler) = state.reconciler {
        reconciler.get_desired().await
    } else {
        DesiredState::default()
    };

    Json(serde_json::json!({
        "desired": {
            "rule_count": desired.rules.len(),
        },
        "actual": {
            "rule_count": 0,
        },
        "drift": {
            "drift_count": 0,
        },
    }))
}

/// List all drivers
pub async fn list_drivers(State(_state): State<Arc<ApiState>>) -> impl IntoResponse {
    // TODO: Get drivers from registry
    Json(serde_json::json!({
        "drivers": [],
        "count": 0,
    }))
}

/// Get driver by ID
pub async fn get_driver(
    State(_state): State<Arc<ApiState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    // TODO: Get driver by ID
    Json(serde_json::json!({
        "id": id,
        "status": "not_found",
    }))
}

/// Restart driver
pub async fn restart_driver(
    State(_state): State<Arc<ApiState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    // TODO: Restart driver
    Json(serde_json::json!({
        "ok": true,
        "driver_id": id,
        "message": "Restart requested",
    }))
}
