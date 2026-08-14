//! Optional HTTP/SSE server wiring for the daemon.
//!
//! The API is part of the daemon process (no separate service): the subsystem
//! managers own the shared snapshot and event bus, `ControlImpl` forwards
//! operator actions through the same typed IPC boundary as the reconciler, and
//! the axum router serves them read-only + action endpoints. Enable it with
//! `BALANSIR_API_BIND=127.0.0.1:8080` (or `[api]` in the config file).

use balansir_api::control::{ControlPlane, DesiredUpdater};
use balansir_common::DesiredState;
use balansir_control::ControlResult;
use std::sync::Arc;
use tracing::info;

use crate::reconciliation::reconciler::Reconciler;
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
    std::env::var("BALANSIR_API_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string())
}

/// Start the HTTP/SSE server on `bind` (empty string disables the API) over
/// the daemon-managed `SubsystemManager` and optional B4 controller handle.
/// The manager ownership loop and the B4 runtime loop are spawned by the
/// caller (main); this function only wires the API and runs until it exits.
pub async fn start_api_server(
    manager: Arc<SubsystemManager>,
    reconciler: Arc<Reconciler>,
    b4_control: Option<crate::b4_manager::B4ManagerHandle>,
    #[cfg(feature = "xray")] xray_control: Option<crate::xray_manager::XrayManagerHandle>,
    bind: String,
) -> Result<(), String> {
    if bind.trim().is_empty() {
        info!("API disabled (empty bind)");
        return Ok(());
    }

    if let Some(handle) = b4_control {
        manager.set_b4_handle(handle).await;
    }
    #[cfg(feature = "xray")]
    if let Some(handle) = xray_control {
        manager.set_xray_handle(handle).await;
    }

    let control: Arc<dyn balansir_common::subsystems::SubsystemControl> =
        Arc::new(ControlImpl::new(Arc::clone(&manager)));
    let snapshot = manager.snapshot();
    let events = manager.event_sender();

    // Wire the policy control plane to the daemon's single reconciler
    // coordinator: same desired/actual stores, same coordinator, same executor.
    // The event bridge is attached to the coordinator's dynamic sink so both
    // background-loop and API-triggered reconciles flow to the WebUI.
    let bridge = Arc::new(balansir_api::control::EventBridge::new(256));
    reconciler.attach_event_sink(bridge.clone());
    let plane = ControlPlane::wrap(
        reconciler.coordinator(),
        reconciler.desired_provider(),
        reconciler.actual_provider(),
        bridge,
        Some(Arc::new(ReconcilerUpdater(Arc::clone(&reconciler)))),
    );

    let state = Arc::new(
        balansir_api::ApiState::new(Arc::new(balansir_common::metrics::SharedMetrics::new()))
            .with_subsystems(control, snapshot, events)
            .with_control(plane),
    );

    balansir_api::start_server(state, &bind).await
}

/// Writable desired-state seam for transactional `/reload`: writes go through
/// the reconciler's `set_desired` (flow compilation + fingerprint included),
/// so an API reload is exactly equivalent to a startup config load.
struct ReconcilerUpdater(Arc<Reconciler>);

#[async_trait::async_trait]
impl DesiredUpdater for ReconcilerUpdater {
    async fn set_desired(&self, state: DesiredState) {
        self.0.set_desired(state).await;
    }

    async fn desired(&self) -> ControlResult<DesiredState> {
        Ok(self.0.desired().await)
    }
}
