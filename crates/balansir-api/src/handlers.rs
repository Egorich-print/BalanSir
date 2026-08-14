//! HTTP handlers for the BalanSir operational API.
//!
//! Handlers talk to the daemon through `ApiSurface` (live ReconcilerApi); the
//! API never reaches into daemon internals. All control-plane handlers return
//! a clear 503 if no surface is installed (e.g. tests without a daemon).

use axum::{
    extract::State,
    http::StatusCode,
    response::{sse::Event, IntoResponse, Sse},
    Json,
};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::ApiState;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventEntry {
    pub timestamp: i64,
    pub event_type: String,
    pub details: String,
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

/// Metrics handler (Prometheus text)
pub async fn metrics(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let body = state.metrics.encode_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}

/// Desired state
pub async fn get_desired(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = &state.api else {
        return Json(serde_json::json!({ "error": "Control plane not available" }));
    };
    let desired = api.desired().await;
    let rules: Vec<_> = desired
        .rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "action": format!("{:?}", r.action),
                "priority": r.priority,
                "flow": r.flow,
            })
        })
        .collect();
    Json(serde_json::json!({
        "rules": rules,
        "rule_count": desired.rules.len(),
        "drivers": desired.drivers.len(),
    }))
}

/// Set desired state (transactional reload)
#[derive(Deserialize)]
pub struct DesiredPayload {
    pub rules: Option<Vec<serde_json::Value>>,
    pub drivers: Option<Vec<serde_json::Value>>,
}

pub async fn set_desired(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<DesiredPayload>,
) -> impl IntoResponse {
    let Some(api) = state.api.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Control plane not available" })),
        );
    };

    // Convert a submitted desired state into the reconcile wire type.
    // Full rule/flow parsing lives on the CLI/config path (DesiredConfig);
    // the API accepts a raw DesiredState for now.
    let state = serde_json::from_value::<balansir_common::DesiredState>(serde_json::json!({
        "rules": payload.rules.unwrap_or_default(),
        "drivers": payload.drivers.unwrap_or_default(),
    }));
    match state {
        Ok(state) => match api.reload(state).await {
            Ok(()) => (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "generation": api.generation().await })),
            ),
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e })),
            ),
        },
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("invalid desired state: {e}") })),
        ),
    }
}

/// Actual state
pub async fn get_actual(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = &state.api else {
        return Json(serde_json::json!({ "error": "Control plane not available" }));
    };
    let actual = api.actual().await;
    let rules: Vec<_> = actual
        .active_rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "action": format!("{:?}", r.action),
                "rule_id": r.rule_id,
            })
        })
        .collect();
    Json(serde_json::json!({
        "active_rules": rules,
        "rule_count": actual.active_rules.len(),
    }))
}

/// Drift: rules in desired but missing/changed in actual
pub async fn get_drift(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = &state.api else {
        return Json(serde_json::json!({ "error": "Control plane not available" }));
    };
    let (desired, actual) = (api.desired().await, api.actual().await);
    let mut items = Vec::new();
    for r in &desired.rules {
        match actual.active_rules.iter().find(|a| a.id == r.id) {
            Some(a) if a.action == r.action => {}
            Some(_) => items.push(serde_json::json!({
                "rule_id": r.id,
                "kind": "changed",
                "details": format!("desired {:?} vs actual", r.action),
            })),
            None => items.push(serde_json::json!({
                "rule_id": r.id,
                "kind": "missing",
                "details": "rule not present in actual state",
            })),
        }
    }
    for a in &actual.active_rules {
        if !desired.rules.iter().any(|r| r.id == a.id) {
            items.push(serde_json::json!({
                "rule_id": a.id,
                "kind": "orphan",
                "details": "rule present in actual but not desired",
            }));
        }
    }
    Json(serde_json::json!({ "drift_count": items.len(), "items": items }))
}

/// Reconciliation plan (explain)
pub async fn get_plan(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = &state.api else {
        return Json(serde_json::json!({ "error": "Control plane not available" }));
    };
    Json(serde_json::json!({ "plan": api.plan().await }))
}

/// Explain current reconciliation
pub async fn get_explain(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = &state.api else {
        return Json(serde_json::json!({ "error": "Control plane not available" }));
    };
    Json(serde_json::json!({ "explain": api.explain().await }))
}

/// Config fingerprint
pub async fn get_fingerprint(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = &state.api else {
        return Json(serde_json::json!({ "error": "Control plane not available" }));
    };
    Json(
        serde_json::json!({ "fingerprint": api.fingerprint().await, "generation": api.generation().await }),
    )
}

/// Trigger a reconcile
pub async fn trigger_reconcile(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = state.api.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Control plane not available" })),
        );
    };
    match api.reconcile().await {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "generation": api.generation().await })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

/// Events snapshot
pub async fn get_events(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let events = if let Some(api) = state.api.as_ref() {
        api.events().snapshot().await
    } else {
        Vec::new()
    };
    Json(serde_json::json!({ "events": events, "count": events.len() }))
}

/// SSE event stream
pub async fn events_stream(
    State(state): State<Arc<ApiState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let receiver = if let Some(api) = state.api.as_ref() {
        api.events().subscribe()
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
    Json(serde_json::json!({ "ready": true }))
}

/// Live check
pub async fn live() -> impl IntoResponse {
    Json(serde_json::json!({ "live": true }))
}

/// Version
pub async fn version() -> impl IntoResponse {
    Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") }))
}

/// Build info
pub async fn build_info() -> impl IntoResponse {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": env!("CARGO_PKG_NAME"),
        "rustc": env!("CARGO_PKG_RUST_VERSION"),
    }))
}

/// Drivers — from the desired config (driver intents), not live processes.
pub async fn list_drivers(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = state.api.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Control plane not available", "drivers": [] })),
        );
    };
    let desired = api.desired().await;
    let drivers: Vec<_> = desired
        .drivers
        .iter()
        .map(|d| {
            serde_json::json!({
                "id": format!("{:?}", d.id),
                "name": d.id.canonical_name(),
                "action": format!("{:?}", d.action),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({ "drivers": drivers, "count": drivers.len() })),
    )
}

pub async fn get_driver(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = state.api.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Control plane not available" })),
        );
    };
    let desired = api.desired().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "drivers": desired.drivers.iter().map(|d| serde_json::json!({
                "id": format!("{:?}", d.id),
                "name": d.id.canonical_name(),
                "action": format!("{:?}", d.action),
            })).collect::<Vec<_>>(),
        })),
    )
}

pub async fn restart_driver() -> impl IntoResponse {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": "driver restart not wired to live processes" })),
    )
}

/// Tailscale status (installed / backend / IP / peers).
pub async fn tailscale_status(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = state.api.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Control plane not available" })),
        );
    };
    (StatusCode::OK, Json(api.tailscale_status().await))
}

/// Bring Tailscale up (authentication flow).
pub async fn tailscale_up(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = state.api.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Control plane not available" })),
        );
    };
    match api.tailscale_up().await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e, "login_required": true })),
        ),
    }
}

/// Bring Tailscale down.
pub async fn tailscale_down(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = state.api.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Control plane not available" })),
        );
    };
    match api.tailscale_down().await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        ),
    }
}

/// QoS status: desired plans + applied interfaces.
pub async fn qos_status(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(api) = state.api.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "Control plane not available" })),
        );
    };
    (StatusCode::OK, Json(api.qos_status().await))
}
