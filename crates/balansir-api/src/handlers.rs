use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use balansir_common::{DesiredState, DesiredRule, Action};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;

use crate::ApiState;

/// Reconciler handle (simplified)
pub struct ReconcilerHandle {
    desired: RwLock<DesiredState>,
    event_log: RwLock<Vec<EventEntry>>,
    reconcile_count: AtomicU64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EventEntry {
    pub timestamp: i64,
    pub event_type: String,
    pub details: String,
}

impl ReconcilerHandle {
    pub fn new() -> Self {
        Self {
            desired: RwLock::new(DesiredState::default()),
            event_log: RwLock::new(Vec::new()),
            reconcile_count: AtomicU64::new(0),
        }
    }

    pub async fn get_desired(&self) -> DesiredState {
        self.desired.read().await.clone()
    }

    pub async fn set_desired(&self, state: DesiredState) {
        let mut desired = self.desired.write().await;
        *desired = state;
    }

    pub async fn add_event(&self, event_type: &str, details: &str) {
        let mut log = self.event_log.write().await;
        log.push(EventEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            event_type: event_type.to_string(),
            details: details.to_string(),
        });

        // Keep last 100 events
        if log.len() > 100 {
            log.remove(0);
        }
    }

    pub async fn get_events(&self) -> Vec<EventEntry> {
        self.event_log.read().await.clone()
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
            .unwrap()
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

    let rules: Vec<serde_json::Value> = desired.rules.iter().map(|r| {
        serde_json::json!({
            "id": r.id,
            "action": format!("{:?}", r.action),
            "priority": r.priority,
        })
    }).collect();

    Json(serde_json::json!({
        "rules": rules,
        "rule_count": desired.rules.len(),
    }))
}

/// Set desired state
pub async fn set_desired(
    State(state): State<Arc<ApiState>>,
) -> impl IntoResponse {
    // Simplified: just return ok for now
    if let Some(ref reconciler) = state.reconciler {
        reconciler.add_event("desired_updated", "via API").await;
    }

    (StatusCode::OK, Json(serde_json::json!({"ok": true, "message": "Use POST with JSON body"})))
}

/// Get drift status
pub async fn get_drift(State(_state): State<Arc<ApiState>>) -> impl IntoResponse {
    // Simplified: return empty drift for now
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
