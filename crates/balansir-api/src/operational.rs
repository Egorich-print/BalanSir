//! Operational control-plane API (mission M6).
//!
//! Extends the existing HTTP surface with:
//! - OTA slot status, boot-confirm, and rollback
//! - VPN profile health diagnostics
//!
//! All mutations go through existing daemon services — no UI-only source of
//! truth, no direct boot-metadata writes from the frontend.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use crate::ApiState;

fn unavailable(msg: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

fn error_response(msg: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// OTA status
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct OtaStatusResponse {
    pub available: bool,
    #[serde(rename = "currentSlot")]
    pub current_slot: Option<String>,
    #[serde(rename = "nextSlot")]
    pub next_slot: Option<String>,
    pub state: Option<String>,
    #[serde(rename = "activeVersion")]
    pub active_version: Option<String>,
    #[serde(rename = "nextVersion")]
    pub next_version: Option<String>,
    #[serde(rename = "rollbackCount")]
    pub rollback_count: Option<u32>,
    #[serde(rename = "lastRollbackReason")]
    pub last_rollback_reason: Option<String>,
    #[serde(rename = "triesRemaining")]
    pub tries_remaining: Option<u8>,
}

/// `GET /ota/status` — current A/B slot state for the WebUI.
pub async fn ota_status() -> Response {
    let result = tokio::task::spawn_blocking(balansir_ota::slot::BootMetadata::load).await;

    match result {
        Ok(Ok(meta)) => {
            let body = OtaStatusResponse {
                available: true,
                current_slot: Some(format!("{:?}", meta.active_slot)),
                next_slot: Some(format!("{:?}", meta.next_slot)),
                state: Some(format!("{:?}", meta.state)),
                active_version: Some(meta.active_version.clone()),
                next_version: if meta.next_version.is_empty() {
                    None
                } else {
                    Some(meta.next_version.clone())
                },
                rollback_count: Some(meta.rollback_count),
                last_rollback_reason: if meta.last_rollback_reason.is_empty() {
                    None
                } else {
                    Some(meta.last_rollback_reason.clone())
                },
                tries_remaining: Some(meta.tries_remaining),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Ok(Err(e)) => (
            StatusCode::OK,
            Json(OtaStatusResponse {
                available: false,
                current_slot: None,
                next_slot: None,
                state: Some(e.to_string()),
                active_version: None,
                next_version: None,
                rollback_count: None,
                last_rollback_reason: None,
                tries_remaining: None,
            }),
        )
            .into_response(),
        Err(e) => unavailable(&format!("OTA task failed: {e}")),
    }
}

/// `POST /ota/boot-confirm` — confirm the current candidate boot as healthy.
pub async fn ota_boot_confirm() -> Response {
    let result = tokio::task::spawn_blocking(|| -> Result<(), balansir_common::Error> {
        let mut meta = balansir_ota::slot::BootMetadata::load()?;
        let version = env!("CARGO_PKG_VERSION").to_string();
        meta.confirm_boot(version)?;
        meta.save()?;
        Ok(())
    })
    .await;

    match result {
        Ok(Ok(())) => (
            StatusCode::OK,
            Json(serde_json::json!({ "confirmed": true })),
        )
            .into_response(),
        Ok(Err(e)) => error_response(&e.to_string()),
        Err(e) => unavailable(&format!("{e}")),
    }
}

/// `POST /ota/rollback` — force rollback to the previous slot.
pub async fn ota_rollback() -> Response {
    let result = tokio::task::spawn_blocking(|| -> Result<String, balansir_common::Error> {
        let mut meta = balansir_ota::slot::BootMetadata::load()?;
        meta.force_rollback("manual rollback via API".to_string())?;
        meta.save()?;
        Ok(format!("{:?}", meta.active_slot))
    })
    .await;

    match result {
        Ok(Ok(slot)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "rolledBackTo": slot })),
        )
            .into_response(),
        Ok(Err(e)) => error_response(&e.to_string()),
        Err(e) => unavailable(&format!("{e}")),
    }
}

// ---------------------------------------------------------------------------
// VPN profile diagnostics
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct VpnProfileDetail {
    #[serde(rename = "profileId")]
    pub profile_id: String,
    pub label: String,
    pub state: String,
    pub weight: u32,
    #[serde(rename = "latencyMs")]
    pub latency_ms: Option<f64>,
    #[serde(rename = "lossPct")]
    pub loss_pct: Option<f64>,
    pub availability: Option<f64>,
    #[serde(rename = "consecutiveSuccesses")]
    pub consecutive_successes: u32,
    #[serde(rename = "consecutiveFailures")]
    pub consecutive_failures: u32,
    #[serde(rename = "failureCount")]
    pub failure_count: u64,
    #[serde(rename = "sampleCount")]
    pub sample_count: u64,
    pub reasons: Vec<String>,
}

/// `GET /vpn/profiles` — detailed VPN profile health with per-profile
/// diagnostics (reasons for state, consecutive counts). Transport/security
/// credentials are intentionally excluded — use `balansir-cli identify`
/// over SSH for identity inspection.
pub async fn vpn_profiles(State(state): State<Arc<ApiState>>) -> Response {
    let Some(snapshot) = &state.subsystem_snapshot else {
        return unavailable("subsystem snapshot not wired");
    };
    let snap = snapshot.read().await;
    let pool = &snap.vpn_pool;

    let profiles: Vec<VpnProfileDetail> = pool
        .profiles
        .iter()
        .map(|p| VpnProfileDetail {
            profile_id: p.profile_id.clone(),
            label: p.label.clone(),
            state: format!("{:?}", p.state),
            weight: p.weight,
            latency_ms: p.latency_ms,
            loss_pct: p.loss_pct,
            availability: p.availability,
            consecutive_successes: p.consecutive_successes,
            consecutive_failures: p.consecutive_failures,
            failure_count: p.failure_count,
            sample_count: p.sample_count,
            reasons: p.reasons.clone(),
        })
        .collect();

    (StatusCode::OK, Json(profiles)).into_response()
}

// ---------------------------------------------------------------------------
// VPN manual profile management
// ---------------------------------------------------------------------------

/// `POST /vpn/profiles/add` — add a VLESS URI as a manual profile.
/// Manual profiles survive subscription refreshes (stored in /persistent).
#[derive(serde::Deserialize)]
pub struct AddProfileBody {
    pub uri: String,
}

pub async fn vpn_add_profile(
    State(_state): State<Arc<ApiState>>,
    body: axum::extract::Json<AddProfileBody>,
) -> Response {
    let uri = body.uri.trim();
    if !uri.starts_with("vless://") {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "only vless:// URIs are supported" })),
        )
            .into_response();
    }
    if uri.len() > 4096 {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": "URI too long (max 4096 bytes)" })),
        )
            .into_response();
    }

    match balansir_vpn::append_manual_profile(uri) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "added": true }))).into_response(),
        Err(e) => error_response(&e),
    }
}

/// `DELETE /vpn/profiles/:id` — remove a manual profile by ID prefix.
pub async fn vpn_remove_profile(
    axum::extract::Path(profile_id): axum::extract::Path<String>,
) -> Response {
    if profile_id.len() < 4 || profile_id.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "profile_id must be 4-64 chars" })),
        )
            .into_response();
    }

    match balansir_vpn::remove_manual_profile(&profile_id) {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({ "removed": true }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "profile not found in manual profiles" })),
        )
            .into_response(),
        Err(e) => error_response(&e),
    }
}
