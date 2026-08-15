//! HTTP surface for the non-policy subsystems (QoS shaping, WAN interfaces,
//! Tailscale). Read handlers serve the unified `SharedSubsystemSnapshot`;
//! write handlers forward to the daemon's `SubsystemControl`, which is the
//! only path that talks to the privileged executor. The WebUI never touches
//! privileged state directly.

use crate::ApiState;
use axum::{
    extract::{Path, State},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    Json,
};
use balansir_common::qos::{QdiscKind, QosConfig, QosDirection};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;

/// Wrap errors as actionable JSON rather than opaque 500s.
#[derive(Serialize)]
struct SubsystemError {
    error: String,
    actionable: bool,
}

fn error_response(detail: &str) -> Response {
    let body = SubsystemError {
        error: detail.to_string(),
        actionable: true,
    };
    (axum::http::StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
}

async fn snapshot_or_unavailable(
    state: &ApiState,
) -> Result<balansir_common::subsystems::SubsystemSnapshot, Response> {
    match state.subsystem_snapshot.clone() {
        Some(s) => Ok(s.read().await),
        None => Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "subsystem managers not attached (daemon not wired?)",
                "actionable": false,
            })),
        )
            .into_response()),
    }
}

#[allow(clippy::result_large_err)]
fn control_or_unavailable(
    state: &ApiState,
) -> Result<Arc<dyn balansir_common::subsystems::SubsystemControl>, Response> {
    state.subsystems.clone().ok_or_else(|| {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "subsystem control not attached (daemon not wired?)",
                "actionable": false,
            })),
        )
            .into_response()
    })
}

/// `GET /subsystems` — full unified snapshot.
pub async fn get_snapshot(State(state): State<Arc<ApiState>>) -> Response {
    match snapshot_or_unavailable(&state).await {
        Ok(snapshot) => Json(snapshot).into_response(),
        Err(resp) => resp,
    }
}

/// `GET /b4` — B4 component state (enabled, per-flow adaptation, MTU
/// ownership drift, pause state, diagnostics).
pub async fn get_b4(State(state): State<Arc<ApiState>>) -> Response {
    let snapshot = match snapshot_or_unavailable(&state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    Json(snapshot.b4).into_response()
}

/// `GET /dpi` — DPI-bypass engine state (enabled, queue, profiles, counters).
pub async fn get_dpi(State(state): State<Arc<ApiState>>) -> Response {
    let snapshot = match snapshot_or_unavailable(&state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    Json(snapshot.dpi).into_response()
}

/// `POST /b4/pause` — pause/resume the B4 adaptation engine.
pub async fn set_b4_paused(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let paused = match body.get("paused").and_then(|v| v.as_bool()) {
        Some(p) => p,
        None => return error_response("body requires \"paused\": true|false"),
    };
    match control.b4_set_paused(paused).await {
        Ok(()) => Json(serde_json::json!({ "paused": paused })).into_response(),
        Err(detail) => error_response(&detail),
    }
}

/// `GET /xray` — Xray transport state (profiles, active endpoint, selection
/// mode, failover/rotation diagnostics).
pub async fn get_xray(State(state): State<Arc<ApiState>>) -> Response {
    let snapshot = match snapshot_or_unavailable(&state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    Json(snapshot.xray).into_response()
}

/// `POST /xray/pause` — pause/resume the Xray transport (stop/start the
/// proxy process; traffic falls back to the direct path while paused).
pub async fn set_xray_paused(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let paused = match body.get("paused").and_then(|v| v.as_bool()) {
        Some(p) => p,
        None => return error_response("body requires \"paused\": true|false"),
    };
    match control.xray_set_paused(paused).await {
        Ok(()) => Json(serde_json::json!({ "paused": paused })).into_response(),
        Err(detail) => error_response(&detail),
    }
}

/// `POST /xray/select` — pin a specific endpoint (manual override; still
/// failover-aware so a dead endpoint cannot pin the network indefinitely).
pub async fn select_xray(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let profile = match body.get("profile").and_then(|v| v.as_str()) {
        Some(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => return error_response("body requires \"profile\": <endpoint name>"),
    };
    match control.xray_select(&profile).await {
        Ok(()) => Json(serde_json::json!({ "pinned": profile })).into_response(),
        Err(detail) => error_response(&detail),
    }
}

/// `POST /xray/rotate` — move to the next enabled endpoint (manual rotation).
pub async fn rotate_xray(State(state): State<Arc<ApiState>>) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    match control.xray_rotate().await {
        Ok(()) => Json(serde_json::json!({ "rotated": true })).into_response(),
        Err(detail) => error_response(&detail),
    }
}

/// `GET /path/decision` — unified path decision (Direct / B4 / VPN pool).
pub async fn get_path_decision(State(state): State<Arc<ApiState>>) -> Response {
    let snapshot = match snapshot_or_unavailable(&state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    Json(snapshot.path_decision).into_response()
}

/// `GET /vpn/pool` — VPN alternative-path pool state (health, selection,
/// load, rotation diagnostics). No credentials exposed.
pub async fn get_vpn_pool(State(state): State<Arc<ApiState>>) -> Response {
    let snapshot = match snapshot_or_unavailable(&state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    Json(snapshot.vpn_pool).into_response()
}

/// `POST /vpn/pause` — pause/resume the VPN pool.
pub async fn set_vpn_paused(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let paused = match body.get("paused").and_then(|v| v.as_bool()) {
        Some(p) => p,
        None => return error_response("body requires \"paused\": true|false"),
    };
    match control.vpn_set_paused(paused).await {
        Ok(()) => Json(serde_json::json!({ "paused": paused })).into_response(),
        Err(detail) => error_response(&detail),
    }
}

/// `POST /vpn/refresh` — trigger a subscription refresh (keeps the known-good
/// pool on failure).
pub async fn refresh_vpn_pool(State(state): State<Arc<ApiState>>) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    match control.vpn_refresh().await {
        Ok(()) => Json(serde_json::json!({ "refreshed": true })).into_response(),
        Err(detail) => error_response(&detail),
    }
}

/// `POST /vpn/rotate` — manual rotation to the next eligible profile.
pub async fn rotate_vpn_pool(State(state): State<Arc<ApiState>>) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    match control.vpn_rotate().await {
        Ok(()) => Json(serde_json::json!({ "rotated": true })).into_response(),
        Err(detail) => error_response(&detail),
    }
}

/// `POST /vpn/pin` — pin a profile (by profile_id) or clear with `null`.
pub async fn pin_vpn_pool(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let profile_id = body
        .get("profile_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    match control.vpn_set_pin(profile_id.clone()).await {
        Ok(()) => Json(serde_json::json!({ "pinned": profile_id })).into_response(),
        Err(detail) => error_response(&detail),
    }
}

/// `GET /qos` — shaping intent, applied qdiscs, capabilities and drift.
pub async fn get_qos(State(state): State<Arc<ApiState>>) -> Response {
    let snapshot = match snapshot_or_unavailable(&state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    Json(serde_json::json!({
        "desired": snapshot.qos.desired,
        "applied": snapshot.qos.applied,
        "capabilities": snapshot.qos.capabilities,
        "drift": snapshot.qos.drift,
        "last_error": snapshot.qos.last_error,
    }))
    .into_response()
}

/// Body for `POST /qos`.
#[derive(Deserialize)]
pub struct QosIntentBody {
    /// One or more shaping policies. An empty list clears all shaping.
    pub interfaces: Vec<QosEntryBody>,
}

#[derive(Deserialize)]
pub struct QosEntryBody {
    pub interface: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    pub bandwidth_mbps: Option<u64>,
    #[serde(default)]
    pub latency_target_ms: Option<u64>,
}

/// `POST /qos` — replace the shaping intent (reconciled by the daemon).
pub async fn set_qos(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<QosIntentBody>,
) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let mut configs = Vec::new();
    for entry in body.interfaces {
        let interface = entry.interface.trim().to_string();
        if interface.is_empty() {
            return error_response("qos interface must not be empty");
        }
        let kind = match entry.kind.as_deref().unwrap_or("fq_codel") {
            "fq_codel" => QdiscKind::FqCodel,
            "cake" => QdiscKind::Cake,
            "ingress" => QdiscKind::Ingress,
            other => return error_response(&format!("unsupported qdisc kind: {other}")),
        };
        let direction = match entry.direction.as_deref().unwrap_or("egress") {
            "egress" => QosDirection::Egress,
            "ingress" => QosDirection::Ingress,
            other => return error_response(&format!("unsupported qos direction: {other}")),
        };
        configs.push(QosConfig {
            interface,
            direction,
            kind,
            bandwidth_bps: entry.bandwidth_mbps.map(|m| m * 1_000_000),
            latency_target_ms: entry.latency_target_ms,
            overhead_bytes: None,
            ecn: true,
            wash: false,
            memory_limit_bytes: None,
            classes: vec![],
            comment: QosConfig::identity(entry.interface.trim()),
        });
    }

    match control.set_qos_intent(configs).await {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => error_response(&e),
    }
}

/// `DELETE /qos/:interface` — remove shaping from one interface.
pub async fn remove_qos(
    State(state): State<Arc<ApiState>>,
    Path(interface): Path<String>,
) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    match control.remove_qos(&interface).await {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => error_response(&e),
    }
}

/// `GET /interfaces` — live interface info.
pub async fn get_interfaces(State(state): State<Arc<ApiState>>) -> Response {
    let snapshot = match snapshot_or_unavailable(&state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    Json(snapshot.interfaces).into_response()
}

/// Body for `POST /interfaces/:interface/mac`.
#[derive(Deserialize)]
pub struct SetMacBody {
    pub mac: String,
}

/// `POST /interfaces/:interface/mac` — clone a WAN MAC (factory MAC kept).
pub async fn set_mac(
    State(state): State<Arc<ApiState>>,
    Path(interface): Path<String>,
    Json(body): Json<SetMacBody>,
) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let mac = body.mac.trim().to_string();
    // Client-side sanity only; the executor validates strictly.
    if !mac
        .split(':')
        .all(|octet| !octet.is_empty() && octet.len() <= 2)
    {
        return error_response("malformed MAC address");
    }
    match control.set_mac(&interface, &mac).await {
        Ok(result) => Json(result).into_response(),
        Err(e) => error_response(&e),
    }
}

/// `POST /interfaces/:interface/mac/restore` — restore the factory MAC.
pub async fn restore_mac(
    State(state): State<Arc<ApiState>>,
    Path(interface): Path<String>,
) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    match control.restore_mac(&interface).await {
        Ok(result) => Json(result).into_response(),
        Err(e) => error_response(&e),
    }
}

/// `GET /tailscale` — tailnet status (never exposes secrets).
pub async fn get_tailscale(State(state): State<Arc<ApiState>>) -> Response {
    let snapshot = match snapshot_or_unavailable(&state).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    Json(serde_json::json!({
        "status": snapshot.tailscale.status,
        "error": snapshot.tailscale.error,
        "pending_op": snapshot.tailscale.pending_op,
    }))
    .into_response()
}

/// Body for `POST /tailscale/up`.
#[derive(Deserialize)]
pub struct TailscaleUpBody {
    #[serde(default)]
    pub auth_key: Option<String>,
}

/// `POST /tailscale/up` — bring the tailnet up (optional auth key).
pub async fn tailscale_up(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<TailscaleUpBody>,
) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    // Auth keys are passed through to the executor once and never logged.
    match control.tailscale_up(body.auth_key).await {
        Ok(result) => Json(result).into_response(),
        Err(e) => error_response(&e),
    }
}

/// `POST /tailscale/down`.
pub async fn tailscale_down(State(state): State<Arc<ApiState>>) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    match control.tailscale_down().await {
        Ok(result) => Json(result).into_response(),
        Err(e) => error_response(&e),
    }
}

/// `POST /tailscale/reconnect`.
pub async fn tailscale_reconnect(State(state): State<Arc<ApiState>>) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    match control.tailscale_reconnect().await {
        Ok(result) => Json(result).into_response(),
        Err(e) => error_response(&e),
    }
}

/// Body for `POST /tailscale/routes`.
#[derive(Deserialize)]
pub struct TailscaleRoutesBody {
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub exit_node: bool,
}

/// `POST /tailscale/routes` — advertise subnet routes / exit node.
pub async fn tailscale_set_routes(
    State(state): State<Arc<ApiState>>,
    Json(body): Json<TailscaleRoutesBody>,
) -> Response {
    let control = match control_or_unavailable(&state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    for route in &body.routes {
        if route.parse::<std::net::IpAddr>().is_err()
            && route.parse::<std::net::Ipv4Addr>().is_err()
            && route.parse::<std::net::Ipv6Addr>().is_err()
        {
            // Subnet routes like "192.168.1.0/24" are validated by the
            // executor's allowlist; only obviously malformed strings are
            // rejected here.
            let prefix_ok = route
                .split('/')
                .nth(1)
                .map(|p| p.parse::<u8>().is_ok())
                .unwrap_or(false);
            let addr_ok = route
                .split('/')
                .next()
                .map(|a| a.parse::<std::net::IpAddr>().is_ok())
                .unwrap_or(false);
            if !(prefix_ok && addr_ok) {
                return error_response(&format!("malformed route: {route}"));
            }
        }
    }
    match control
        .tailscale_set_routes(body.routes, body.exit_node)
        .await
    {
        Ok(result) => Json(result).into_response(),
        Err(e) => error_response(&e),
    }
}

/// `GET /subsystems/events` — SSE stream of subsystem state changes.
/// Reconnects fast (default EventSource retry); no client polling needed.
pub async fn events_stream(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let events = match state.subsystem_events.clone() {
        Some(sender) => sender,
        None => {
            let body = serde_json::json!({
                "error": "subsystem events not attached (daemon not wired?)",
                "actionable": false,
            });
            return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
        }
    };

    let stream = BroadcastStream::new(events.subscribe()).filter_map(|item| async move {
        match item {
            Ok(event) => {
                let name = event.name();
                let payload = serde_json::to_string(&event).unwrap_or_else(|_| "{}".into());
                Some(Ok::<Event, Infallible>(
                    Event::default().event(name).data(payload),
                ))
            }
            Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(_)) => {
                // Subscriber too slow: the next full snapshot fetch reconciles.
                Some(Ok::<Event, Infallible>(
                    Event::default().event("resync_required").data("{}"),
                ))
            }
        }
    });

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(20)))
        .into_response()
}
