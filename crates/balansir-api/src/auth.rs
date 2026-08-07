//! API token authentication.
//!
//! Opt-in bearer-token auth. Enabled only when `BALANSIR_API_TOKEN` is set, so
//! health probes and local unauthenticated installs keep working.

use axum::http::{header::AUTHORIZATION, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::sync::Arc;

const TOKEN_ENV: &str = "BALANSIR_API_TOKEN";

/// Read the configured token once at startup (empty when auth disabled).
pub fn token_from_env() -> Option<Arc<str>> {
    match std::env::var(TOKEN_ENV) {
        Ok(t) if !t.is_empty() => Some(Arc::from(t)),
        _ => None,
    }
}

/// Verify the bearer token in the request against the configured token.
/// Returns `Ok(())` when auth is disabled or the token matches.
pub fn verify_header(
    headers: &axum::http::HeaderMap,
    expected: &Option<Arc<str>>,
) -> Result<(), Box<Response>> {
    let expected = match expected {
        Some(t) => t,
        None => return Ok(()), // auth disabled
    };

    let provided = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    if provided == Some(expected.as_ref()) {
        Ok(())
    } else {
        Err(Box::new(unauthorized()))
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response()
}
