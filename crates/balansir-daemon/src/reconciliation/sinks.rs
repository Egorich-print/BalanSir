//! Event sinks bridging the coordinator's events to daemon-side logging.

use balansir_control::traits::EventSink;
use balansir_control::{ControlEvent, ControlResult};
use std::sync::Arc;

/// Logs control-plane events at trace level.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingEventSink;

#[async_trait::async_trait]
impl EventSink for TracingEventSink {
    async fn emit(&self, event: &ControlEvent) -> ControlResult<()> {
        tracing::trace!(event = event.name(), "control event");
        Ok(())
    }
}

/// Event sink that fans events out to multiple sinks (tracing + API bridge).
///
/// The daemon installs this so control-plane events reach both the log and the
/// WebUI SSE stream without a second planning authority.
#[derive(Clone)]
pub struct FanoutEventSink {
    sinks: Vec<Arc<dyn EventSink>>,
}

impl FanoutEventSink {
    pub fn new(sinks: Vec<Arc<dyn EventSink>>) -> Self {
        Self { sinks }
    }
}

#[async_trait::async_trait]
impl EventSink for FanoutEventSink {
    async fn emit(&self, event: &ControlEvent) -> ControlResult<()> {
        for sink in &self.sinks {
            sink.emit(event).await?;
        }
        Ok(())
    }
}

/// Bridges `ControlEvent`s from the coordinator into the WebUI `ApiEventBridge`.
pub struct ApiBridgeEventSink {
    bridge: Arc<balansir_api::surface::ApiEventBridge>,
}

impl ApiBridgeEventSink {
    pub fn new(bridge: Arc<balansir_api::surface::ApiEventBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait::async_trait]
impl EventSink for ApiBridgeEventSink {
    async fn emit(&self, event: &ControlEvent) -> ControlResult<()> {
        self.bridge
            .record(balansir_api::surface::ApiEvent {
                timestamp: chrono::Utc::now().timestamp(),
                event_type: event.name().to_string(),
                details: match event {
                    ControlEvent::Failed { error } => error.clone(),
                    ControlEvent::StepFailed { error, .. } => error.clone(),
                    ControlEvent::ReconciliationRequested(reason) => {
                        format!("requested via {}", reason.label())
                    }
                    other => format!("{other:?}"),
                },
            })
            .await;
        Ok(())
    }
}
