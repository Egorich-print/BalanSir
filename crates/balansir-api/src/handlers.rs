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

use crate::control::driver_from_name;
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
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": crate::uptime_seconds(),
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
    let Some(plane) = &state.control else {
        return Json(serde_json::json!({
            "error": "Control plane not available",
            "rules": [],
            "rule_count": 0,
        }));
    };

    let desired = match plane.desired().await {
        Ok(d) => d,
        Err(e) => {
            return Json(serde_json::json!({
                "error": e.to_string(),
                "rules": [],
                "rule_count": 0,
            }))
        }
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
pub async fn set_desired(
    State(state): State<Arc<ApiState>>,
    Json(candidate): Json<balansir_common::DesiredState>,
) -> impl IntoResponse {
    let Some(plane) = state.control.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ok": false,
                "error": "Control plane not available",
            })),
        );
    };

    // Transactional hot reload (ADR-010): the candidate is staged through the
    // coordinator's reconcile cycle; on failure the previous state remains live.
    match plane.reload_api(candidate).await {
        Ok(()) => {
            state.metrics.get().record_reconciliation();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "generation": plane.generation(),
                    "message": "Desired state applied",
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": e.to_string(),
                "message": "Desired state rejected; previous state kept",
            })),
        ),
    }
}

/// Get drift status (desired vs actual diff).
pub async fn get_drift(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(plane) = &state.control else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Control plane not available",
                "drift_count": 0,
                "items": [],
            })),
        );
    };

    let (desired, actual) = match (plane.desired().await, plane.actual().await) {
        (Ok(d), Ok(a)) => (d, a),
        (Err(e), _) | (_, Err(e)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": e.to_string(),
                    "drift_count": 0,
                    "items": [],
                })),
            )
        }
    };

    let mut items = Vec::new();
    for rule in &desired.rules {
        let in_actual = actual.active_rules.iter().find(|r| r.id == rule.id);
        match in_actual {
            Some(ar) if ar.action == rule.action => {}
            Some(ar) => items.push(serde_json::json!({
                "rule_id": rule.id,
                "kind": "updated",
                "details": format!("desired {:?}, actual {:?}", rule.action, ar.action),
            })),
            None => items.push(serde_json::json!({
                "rule_id": rule.id,
                "kind": "missing",
                "details": format!("rule {} not present", rule.id),
            })),
        }
    }
    for ar in &actual.active_rules {
        if !desired.rules.iter().any(|r| r.id == ar.id) {
            items.push(serde_json::json!({
                "rule_id": ar.id,
                "kind": "extra",
                "details": format!("rule {} not in desired state", ar.id),
            }));
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "drift_count": items.len(),
            "items": items,
        })),
    )
}

/// Trigger manual reconciliation
pub async fn trigger_reconcile(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(plane) = state.control.as_ref() else {
        return Json(serde_json::json!({
            "ok": false,
            "error": "Control plane not available",
        }));
    };

    match plane.reconcile_api().await {
        Ok(()) => {
            state.metrics.get().record_reconciliation();
            Json(serde_json::json!({
                "ok": true,
                "generation": plane.generation(),
            }))
        }
        Err(balansir_control::error::ControlError::ReconcileInProgress) => {
            Json(serde_json::json!({
                "ok": false,
                "error": "Reconciliation already in progress",
            }))
        }
        Err(e) => Json(serde_json::json!({
            "ok": false,
            "error": e.to_string(),
        })),
    }
}

/// Get events
pub async fn get_events(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let events = if let Some(plane) = state.control.as_ref() {
        plane.get_events().await
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
    let receiver = if let Some(plane) = state.control.as_ref() {
        plane.subscribe_events()
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
pub async fn get_actual(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(plane) = &state.control else {
        return Json(serde_json::json!({
            "error": "Control plane not available",
            "rules": [],
            "rule_count": 0,
        }));
    };

    let actual = match plane.actual().await {
        Ok(a) => a,
        Err(e) => {
            return Json(serde_json::json!({
                "error": e.to_string(),
                "rules": [],
                "rule_count": 0,
            }))
        }
    };

    let mut rules: Vec<serde_json::Value> = Vec::with_capacity(actual.active_rules.len());
    for r in &actual.active_rules {
        // Priority is not part of the executor's actual rule inventory (the
        // executor knows verdicts, not policy priority). Map it from the
        // desired rules so the WebUI renders P<priority> honestly.
        let priority = match r.rule_id {
            Some(id) => plane
                .desired()
                .await
                .ok()
                .and_then(|d| d.rules.iter().find(|dr| dr.id == id).map(|dr| dr.priority)),
            None => None,
        };
        rules.push(serde_json::json!({
            "id": r.id,
            "action": format!("{:?}", r.action),
            "rule_id": r.rule_id,
            "priority": priority,
        }));
    }

    Json(serde_json::json!({
        "rules": rules,
        "rule_count": actual.active_rules.len(),
    }))
}

/// Get combined state (desired + actual + drift)
pub async fn get_state(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(plane) = &state.control else {
        return Json(serde_json::json!({
            "error": "Control plane not available",
        }));
    };

    let (desired, actual) = match (plane.desired().await, plane.actual().await) {
        (Ok(d), Ok(a)) => (d, a),
        (Err(e), _) | (_, Err(e)) => return Json(serde_json::json!({"error": e.to_string()})),
    };

    let in_actual: std::collections::HashSet<u32> =
        actual.active_rules.iter().map(|r| r.id).collect();
    let drift_count = desired
        .rules
        .iter()
        .filter(|r| !in_actual.contains(&r.id))
        .count();

    Json(serde_json::json!({
        "desired": {
            "rule_count": desired.rules.len(),
        },
        "actual": {
            "rule_count": actual.active_rules.len(),
        },
        "drift": {
            "drift_count": drift_count,
        },
        "generation": plane.generation(),
    }))
}

/// List all configured drivers
pub async fn list_drivers(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let Some(plane) = &state.control else {
        return Json(serde_json::json!({
            "error": "Control plane not available",
            "drivers": [],
            "count": 0,
        }));
    };

    match plane.drivers().await {
        Ok(drivers) => Json(serde_json::json!({
            "drivers": drivers,
            "count": drivers.len(),
        })),
        Err(e) => Json(serde_json::json!({
            "error": e.to_string(),
            "drivers": [],
            "count": 0,
        })),
    }
}

/// Get driver by ID or name
pub async fn get_driver(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let Some(plane) = &state.control else {
        return Json(serde_json::json!({
            "id": id,
            "status": "not_found",
        }));
    };

    let drivers = plane.drivers().await.unwrap_or_default();

    let driver_id = driver_from_name(&id).map(|d| d.as_u32());
    match drivers
        .iter()
        .find(|d| Some(d.id) == driver_id || d.name.eq_ignore_ascii_case(&id))
    {
        Some(d) => Json(serde_json::json!({
            "id": d.id,
            "name": d.name,
            "status": d.state,
        })),
        None => Json(serde_json::json!({
            "id": id,
            "status": "not_found",
        })),
    }
}

/// Restart a driver by ID or name.
///
/// This endpoint is **not wired** to the runtime driver lifecycle: the API
/// control plane only drives policy reconciliation, while transport driver
/// restart lives in the privileged lifecycle manager (IPC `RestartDriver`).
/// Responding "Restart requested" while nothing restarts would be a lie, so
/// the request is rejected honestly instead. The WebUI does not expose this
/// control; operators use the CLI/lifecycle path.
pub async fn restart_driver(
    State(state): State<Arc<ApiState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let Some(_plane) = &state.control else {
        return Json(serde_json::json!({
            "ok": false,
            "driver_id": id,
            "message": "Control plane not available",
        }));
    };

    let _driver_id = match driver_from_name(&id) {
        Some(d) => d,
        None => {
            return Json(serde_json::json!({
                "ok": false,
                "driver_id": id,
                "message": "Unknown driver",
            }))
        }
    };

    Json(serde_json::json!({
        "ok": false,
        "driver_id": id,
        "message": "driver restart is not wired through the API control plane; use the operator CLI (IPC RestartDriver)",
    }))
}
