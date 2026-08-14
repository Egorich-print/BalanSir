//! Reconciler API bridge (WebUI backend).
//!
//! Implements `balansir_api::surface::ApiSurface` over the daemon's
//! `Reconciler` (the single planning authority). The HTTP/SSE layer depends
//! only on the trait; the daemon supplies this implementation, so there is no
//! dependency cycle and exactly one reconcile authority.

use crate::reconciliation::Reconciler;
use balansir_api::surface::{ApiEventBridge, ApiSurface};
use balansir_common::metrics::SharedMetrics;
use balansir_common::{ActualState, DesiredState};
use std::sync::Arc;

/// Live API surface over the reconciler.
///
/// Thin by design: every method delegates to `Reconciler`, so the API cannot
/// diverge from the reconcile path, ownership or privilege separation.
pub struct ReconcilerApi {
    reconciler: Arc<Reconciler>,
    metrics: Arc<SharedMetrics>,
    events: Arc<ApiEventBridge>,
}

impl ReconcilerApi {
    pub fn new(
        reconciler: Arc<Reconciler>,
        metrics: Arc<SharedMetrics>,
        events: Arc<ApiEventBridge>,
    ) -> Self {
        Self {
            reconciler,
            metrics,
            events,
        }
    }

    pub fn reconciler(&self) -> Arc<Reconciler> {
        Arc::clone(&self.reconciler)
    }
}

#[async_trait::async_trait]
impl ApiSurface for ReconcilerApi {
    async fn desired(&self) -> DesiredState {
        self.reconciler.get_desired().await
    }

    async fn actual(&self) -> ActualState {
        self.reconciler.get_actual().await
    }

    async fn plan(&self) -> String {
        self.reconciler.explain().await
    }

    async fn explain(&self) -> String {
        self.reconciler.explain().await
    }

    async fn fingerprint(&self) -> Option<u64> {
        self.reconciler.config_fingerprint().await
    }

    async fn generation(&self) -> u64 {
        self.reconciler.generation()
    }

    async fn reload(&self, state: DesiredState) -> Result<(), String> {
        self.reconciler
            .reload(state, balansir_control::ReconcileReason::ApiRequest)
            .await
            .map_err(|e| e.to_string())
    }

    async fn reconcile(&self) -> Result<(), String> {
        self.reconciler.reconcile().await.map_err(|e| e.to_string())
    }

    async fn dns_resync(&self) -> bool {
        self.reconciler.dns_resync().await
    }

    fn metrics(&self) -> Arc<SharedMetrics> {
        Arc::clone(&self.metrics)
    }

    fn events(&self) -> Arc<ApiEventBridge> {
        Arc::clone(&self.events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconciliation::dummy::DummyExecutorAdapter;
    use crate::reconciliation::{Reconciler, ReconcilerConfig};

    #[tokio::test]
    async fn api_surface_reports_reconciler_state() {
        let bridge = Arc::new(balansir_api::surface::ApiEventBridge::new(16));
        let reconciler = Arc::new(Reconciler::new_with_api(
            DesiredState::default(),
            Arc::new(DummyExecutorAdapter::new()),
            ReconcilerConfig::default(),
            Arc::clone(&bridge),
        ));
        let api = ReconcilerApi::new(reconciler, Arc::new(SharedMetrics::new()), bridge);

        // Initially empty desired.
        let d = api.desired().await;
        assert_eq!(d.rules.len(), 0);
        assert!(api.fingerprint().await.is_none());
        assert!(api.reconcile().await.is_ok());
    }
}
