//! Optional HTTP/SSE server wiring for the daemon.
//!
//! The API is part of the daemon process (no separate service): the subsystem
//! managers own the shared snapshot and event bus, `ControlImpl` forwards
//! operator actions through the same typed IPC boundary as the reconciler, and
//! the axum router serves them read-only + action endpoints. Enable it with
//! `BALANSIR_API_BIND=127.0.0.1:8080` (or `[api]` in the config file).

use std::sync::Arc;
use tracing::info;

use crate::reconciliation::ExecutorClient;
use crate::subsystems::{ControlImpl, SubsystemManager};

/// Bind address resolution order: `[api] bind` from BALANSIR_CONFIG, then
/// BALANSIR_API_BIND, then the default loopback.
pub fn api_bind() -> String {
    if let Ok(config) = std::env::var("BALANSIR_CONFIG") {
        if let Ok(text) = std::fs::read_to_string(&config) {
            if let Ok(parsed) = text.parse::<toml::Table>() {
                if let Some(api) = parsed.get("api").and_then(|v| v.as_table()) {
                    if let Some(enabled) = api.get("enabled").and_then(|v| v.as_bool()) {
                        if !enabled {
                            return String::new();
                        }
                    }
                    if let Some(bind) = api.get("bind").and_then(|v| v.as_str()) {
                        if !bind.trim().is_empty() {
                            return bind.trim().to_string();
                        }
                    }
                }
            }
        }
    }
    std::env::var("BALANSIR_API_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
}

/// Start the subsystem managers loop and the HTTP/SSE server on `bind`
/// (empty string disables the API). Runs until the server exits.
pub async fn start_api_server(
    executor: Arc<ExecutorClient>,
    bind: String,
) -> Result<(), String> {
    if bind.trim().is_empty() {
        info!("API disabled (empty bind)");
        return Ok(());
    }

    let manager = Arc::new(SubsystemManager::new(executor));
    manager
        .set_interface_filter(std::env::var("BALANSIR_INTERFACES").unwrap_or_default())
        .await;

    // Ownership loop: observe + converge every few seconds.
    let loop_manager = Arc::clone(&manager);
    tokio::spawn(async move {
        loop_manager.run_loop().await;
    });

    let control: Arc<dyn balansir_common::subsystems::SubsystemControl> =
        Arc::new(ControlImpl::new(Arc::clone(&manager)));
    let snapshot = manager.snapshot();
    let events = manager.event_sender();

    let state = Arc::new(
        balansir_api::ApiState::new(Arc::new(balansir_common::metrics::SharedMetrics::new()))
            .with_subsystems(control, snapshot, events),
    );

    balansir_api::start_server(state, &bind).await
}
