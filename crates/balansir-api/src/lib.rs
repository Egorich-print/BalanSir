use axum::{
    extract::{Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::net::TcpListener;

pub mod auth;
pub mod handlers;

/// API state
pub struct ApiState {
    pub metrics: Arc<balansir_common::metrics::SharedMetrics>,
    pub reconciler: Option<Arc<crate::handlers::ReconcilerHandle>>,
    pub api_token: Option<Arc<str>>,
}

impl ApiState {
    pub fn new(metrics: Arc<balansir_common::metrics::SharedMetrics>) -> Self {
        Self {
            metrics,
            reconciler: None,
            api_token: auth::token_from_env(),
        }
    }
}

/// Health check response
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

/// Metrics response
#[derive(Serialize)]
pub struct MetricsResponse {
    pub content_type: String,
    pub body: String,
}

/// Desired state response
#[derive(Serialize)]
pub struct DesiredResponse {
    pub rules: Vec<DesiredRuleInfo>,
    pub rule_count: usize,
}

#[derive(Serialize)]
pub struct DesiredRuleInfo {
    pub id: u32,
    pub action: String,
    pub priority: u32,
}

/// Drift response
#[derive(Serialize)]
pub struct DriftResponse {
    pub drift_count: usize,
    pub items: Vec<DriftItemInfo>,
}

#[derive(Serialize)]
pub struct DriftItemInfo {
    pub rule_id: u32,
    pub kind: String,
    pub details: String,
}

/// Create API router
pub fn create_router(state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/", get(index))
        // Health & Status
        .route("/health", get(handlers::health))
        .route("/ready", get(handlers::ready))
        .route("/live", get(handlers::live))
        .route("/version", get(handlers::version))
        .route("/build-info", get(handlers::build_info))
        // Metrics
        .route("/metrics", get(handlers::metrics))
        // State
        .route("/desired", get(handlers::get_desired))
        .route("/desired", post(handlers::set_desired))
        .route("/actual", get(handlers::get_actual))
        .route("/state", get(handlers::get_state))
        .route("/drift", get(handlers::get_drift))
        // Drivers
        .route("/drivers", get(handlers::list_drivers))
        .route("/drivers/:id", get(handlers::get_driver))
        .route("/drivers/:id/restart", post(handlers::restart_driver))
        // Actions
        .route("/reconcile", post(handlers::trigger_reconcile))
        // Events
        .route("/events", get(handlers::get_events))
        .route("/events/stream", get(handlers::events_stream))
        .with_state(state.clone())
        // Token auth is opt-in: only enforced when BALANSIR_API_TOKEN is set,
        // so it does not break health probes or local unauthenticated installs.
        .layer(middleware::from_fn_with_state(state, auth_middleware))
}

/// Index page
async fn index() -> impl IntoResponse {
    Json(serde_json::json!({
        "name": "BalanSir API",
        "version": "0.1.0",
        "endpoints": [
            "/health",
            "/metrics",
            "/desired",
            "/drift",
            "/reconcile",
            "/events"
        ]
    }))
}

/// Start API server
pub async fn start_server(state: Arc<ApiState>, port: u16) -> Result<(), String> {
    let app = create_router(state);

    // Bind loopback by default; never expose the unauthenticated management
    // API on all interfaces out of the box.
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .map_err(|e| format!("Failed to bind: {}", e))?;

    tracing::info!("API server listening on 127.0.0.1:{}", port);

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("Server error: {}", e))
}

/// Reject requests without a valid bearer token when auth is enabled.
async fn auth_middleware(
    State(state): State<Arc<ApiState>>,
    request: Request,
    next: Next,
) -> Response {
    if let Err(response) = auth::verify_header(request.headers(), &state.api_token) {
        return *response;
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_index() {
        let state = Arc::new(ApiState::new(Arc::new(
            balansir_common::metrics::SharedMetrics::new(),
        )));
        let app = create_router(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resp = reqwest::get(format!("http://{}/", addr)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["name"], "BalanSir API");
    }

    #[tokio::test]
    async fn test_auth_rejects_wrong_token() {
        let mut state = ApiState::new(Arc::new(balansir_common::metrics::SharedMetrics::new()));
        state.api_token = Some(Arc::from("sekret"));
        let state = Arc::new(state);
        let app = create_router(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();

        let no_auth = client
            .get(format!("http://{}/", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(no_auth.status(), StatusCode::UNAUTHORIZED);

        let bad = client
            .get(format!("http://{}/", addr))
            .bearer_auth("wrong")
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);

        let ok = client
            .get(format!("http://{}/", addr))
            .bearer_auth("sekret")
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    }
}
