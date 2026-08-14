//! Event sinks bridging the coordinator's events to daemon-side logging.

use balansir_control::traits::EventSink;
use balansir_control::{ControlEvent, ControlResult};

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
