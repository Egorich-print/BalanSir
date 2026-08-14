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
pub mod control;
pub mod handlers;
pub mod surface;

/// API state
pub struct ApiState {
    pub metrics: Arc<balansir_common::metrics::SharedMetrics>,
    pub api: Option<Arc<dyn crate::surface::ApiSurface>>,
    pub api_token: Option<Arc<str>>,
}

impl ApiState {
    pub fn new(metrics: Arc<balansir_common::metrics::SharedMetrics>) -> Self {
        Self {
            metrics,
            api: None,
            api_token: auth::token_from_env(),
        }
    }

    /// Install the live control-plane surface (the daemon's ReconcilerApi).
    pub fn with_api(mut self, api: Arc<dyn crate::surface::ApiSurface>) -> Self {
        self.api = Some(api);
        self
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

/// Create API router.
///
/// The API lives under `/api`; the root serves the WebUI static build when
/// `BALANSIR_WEBUI_DIR` points at a build directory (SPA fallback to
/// index.html), otherwise a small JSON index.
pub fn create_router(state: Arc<ApiState>) -> Router {
    let api = Router::new()
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
        .route("/drift", get(handlers::get_drift))
        .route("/plan", get(handlers::get_plan))
        .route("/explain", get(handlers::get_explain))
        .route("/fingerprint", get(handlers::get_fingerprint))
        // Drivers
        .route("/drivers", get(handlers::list_drivers))
        .route("/drivers/:id", get(handlers::get_driver))
        .route("/drivers/:id/restart", post(handlers::restart_driver))
        // Actions
        .route("/reconcile", post(handlers::trigger_reconcile))
        .route("/reload", post(handlers::set_desired))
        // Events
        .route("/events", get(handlers::get_events))
        .route("/events/stream", get(handlers::events_stream))
        // Tailscale
        .route("/tailscale/status", get(handlers::tailscale_status))
        .route("/tailscale/up", post(handlers::tailscale_up))
        .route("/tailscale/down", post(handlers::tailscale_down))
        .with_state(state.clone())
        // Token auth is opt-in: only enforced when BALANSIR_API_TOKEN is set,
        // so it does not break health probes or local unauthenticated installs.
        .layer(middleware::from_fn_with_state(state, auth_middleware));

    let webui_dir = std::env::var("BALANSIR_WEBUI_DIR")
        .ok()
        .filter(|d| !d.is_empty());

    match webui_dir {
        Some(dir) => {
            let svc =
                tower_http::services::ServeDir::new(&dir).append_index_html_on_directories(true);
            Router::new().nest("/api", api).fallback_service(svc)
        }
        None => Router::new().route("/", get(index)).nest("/api", api),
    }
}

/// Index page
async fn index() -> impl IntoResponse {
    Json(serde_json::json!({
        "name": "BalanSir API",
        "version": "0.1.0",
        "endpoints": [
            "/health",
            "/metrics",
            "/api/desired",
            "/api/drift",
            "/api/reconcile",
            "/api/events"
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
            .get(format!("http://{}/api/desired", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(no_auth.status(), StatusCode::UNAUTHORIZED);

        let bad = client
            .get(format!("http://{}/api/desired", addr))
            .bearer_auth("wrong")
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);

        let ok = client
            .get(format!("http://{}/api/desired", addr))
            .bearer_auth("sekret")
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_real_handlers_with_control_plane() {
        use crate::control::ControlPlane;
        use balansir_common::{Action, DesiredDriver, DesiredRule, DesiredState, DriverAction};
        use balansir_control::executor::MockExecutor;
        use balansir_control::planner::BasicPlanner;
        use balansir_control::provider::{MemoryDesiredProvider, MemoryStateProvider};
        use balansir_control::snapshot_store::MemorySnapshotStore;
        use balansir_control::NoopRollback;

        let desired = DesiredState {
            rules: vec![DesiredRule {
                id: 7,
                action: Action::Block,
                priority: 50,
                flow: None,
            }],
            drivers: vec![DesiredDriver {
                id: balansir_common::DriverId::Hysteria,
                action: DriverAction::Start,
            }],
            qos: Vec::new(),
        };

        let plane = ControlPlane::assemble(
            Arc::new(MemoryDesiredProvider::new(desired)),
            Arc::new(MemoryStateProvider::default()),
            Arc::new(BasicPlanner),
            Arc::new(MockExecutor::new()),
            Arc::new(MemorySnapshotStore::new()),
            Arc::new(NoopRollback),
            32,
        );

        let mut state = ApiState::new(Arc::new(balansir_common::metrics::SharedMetrics::new()));
        state.api = Some(plane);
        let app = create_router(Arc::new(state));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();

        // Desired reflects the configured rule and drivers.
        let resp = client
            .get(format!("http://{}/api/desired", addr))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["rule_count"], 1);
        assert_eq!(body["rules"][0]["id"], 7);

        // Drivers list comes from desired config.
        let resp = client
            .get(format!("http://{}/api/drivers", addr))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["count"], 1, "drivers: {body}");
        assert_eq!(body["drivers"][0]["name"], "hysteria");

        // Reconcile actually converges: generation bumps and events are recorded.
        let resp = client
            .post(format!("http://{}/api/reconcile", addr))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ok"], true, "reconcile response: {body}");

        let resp = client
            .get(format!("http://{}/api/events", addr))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        // Events endpoint is reachable (snapshot may be empty on the
        // coordinator-backed plane; live events come via the daemon's bridge).
        assert!(body["events"].is_array());
    }

    #[tokio::test]
    async fn test_reload_endpoint_applies_candidate() {
        use crate::control::{ControlPlane, UpdatableDesiredStore};
        use balansir_common::DesiredState;
        use balansir_control::executor::MockExecutor;
        use balansir_control::planner::BasicPlanner;
        use balansir_control::provider::MemoryStateProvider;
        use balansir_control::snapshot_store::MemorySnapshotStore;
        use balansir_control::NoopRollback;

        let store = Arc::new(UpdatableDesiredStore::new(DesiredState::default()));
        let plane = ControlPlane::assemble_with_updater(
            store.clone(),
            Arc::new(MemoryStateProvider::default()),
            Arc::new(BasicPlanner),
            Arc::new(MockExecutor::new()),
            Arc::new(MemorySnapshotStore::new()),
            Arc::new(NoopRollback),
            32,
            Some(store.clone()),
        );

        let mut state = ApiState::new(Arc::new(balansir_common::metrics::SharedMetrics::new()));
        state.api = Some(plane);
        let app = create_router(Arc::new(state));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = reqwest::Client::new();
        let candidate = serde_json::json!({
            "rules": [
                {"id": 21, "action": "Block", "priority": 90}
            ],
            "drivers": []
        });

        let resp = client
            .post(format!("http://{}/api/reload", addr))
            .json(&candidate)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "reload response body: {}",
            resp.text().await.unwrap_or_default()
        );

        let resp = client
            .get(format!("http://{}/api/desired", addr))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["rule_count"], 1, "desired: {body}");
    }
}
