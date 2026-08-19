use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::RwLock;

/// Label for the aggregated `balansir_drivers` gauge: the health tier name.
/// Keeps Prometheus cardinality bounded to exactly four label values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, prometheus_client::encoding::EncodeLabelSet)]
pub(crate) struct TierLabel {
    tier: &'static str,
}

const TIER_NAMES: [&str; 4] = ["healthy", "degraded", "failing", "disabled"];

/// BalanSir metrics collector
pub struct Metrics {
    registry: RwLock<Registry>,

    // Counters
    pub reconciliations_total: Counter,
    pub reconciliation_failures_total: Counter,

    // Gauges
    pub active_rules: Gauge,
    pub desired_rules: Gauge,

    // Driver observability
    drivers: Family<TierLabel, Gauge>,
    pub driver_lifecycle_transitions: Counter,
}

impl Metrics {
    /// Create new metrics
    pub fn new() -> Self {
        let mut registry = Registry::default();

        // Counter names are registered WITHOUT the `_total` suffix: the
        // Prometheus text encoder appends it for counter metrics, so adding it
        // here would emit `balansir_reconciliations_total_total`.
        let reconciliations_total = Counter::default();
        registry.register(
            "balansir_reconciliations",
            "Total number of reconciliation cycles",
            reconciliations_total.clone(),
        );

        let reconciliation_failures_total = Counter::default();
        registry.register(
            "balansir_reconciliation_failures",
            "Total number of failed reconciliation cycles",
            reconciliation_failures_total.clone(),
        );

        let active_rules = Gauge::default();
        registry.register(
            "balansir_active_rules",
            "Number of active rules",
            active_rules.clone(),
        );

        let desired_rules = Gauge::default();
        registry.register(
            "balansir_desired_rules",
            "Number of desired rules",
            desired_rules.clone(),
        );

        let drivers = Family::<TierLabel, Gauge>::default();
        registry.register(
            "balansir_drivers",
            "Drivers per health tier",
            drivers.clone(),
        );

        let driver_lifecycle_transitions = Counter::default();
        registry.register(
            "balansir_driver_lifecycle_transitions",
            "Total driver lifecycle transitions",
            driver_lifecycle_transitions.clone(),
        );

        Self {
            registry: RwLock::new(registry),
            reconciliations_total,
            reconciliation_failures_total,
            active_rules,
            desired_rules,
            drivers,
            driver_lifecycle_transitions,
        }
    }

    /// Encode metrics in Prometheus text format
    pub fn encode_metrics(&self) -> String {
        let registry = self.registry.read().unwrap_or_else(|e| e.into_inner());
        let mut buffer = String::new();
        let _ = encode(&mut buffer, &registry);
        buffer
    }

    /// Increment reconciliation counter
    pub fn record_reconciliation(&self) {
        self.reconciliations_total.inc();
    }

    /// Record reconciliation failure
    pub fn record_reconciliation_failure(&self) {
        self.reconciliation_failures_total.inc();
    }

    /// Set active rules gauge
    pub fn set_active_rules(&self, count: i64) {
        self.active_rules.set(count);
    }

    /// Set desired rules gauge
    pub fn set_desired_rules(&self, count: i64) {
        self.desired_rules.set(count);
    }

    /// Set per-tier driver counts. `counts` is indexed by `HealthTier::as_u8`
    /// (Healthy=0, Degraded=1, Failing=2, Disabled=3).
    pub fn set_driver_tiers(&self, counts: [i64; 4]) {
        for (idx, &count) in counts.iter().enumerate() {
            self.drivers
                .get_or_create(&TierLabel {
                    tier: TIER_NAMES[idx],
                })
                .set(count);
        }
    }

    /// Record a driver lifecycle transition (state change).
    pub fn record_driver_lifecycle_transition(&self) {
        self.driver_lifecycle_transitions.inc();
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared metrics instance
pub struct SharedMetrics {
    metrics: RwLock<Metrics>,
}

impl SharedMetrics {
    /// Create new shared metrics
    pub fn new() -> Self {
        Self {
            metrics: RwLock::new(Metrics::new()),
        }
    }

    /// Get metrics reference
    pub fn get(&self) -> std::sync::RwLockReadGuard<'_, Metrics> {
        self.metrics.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Encode metrics in Prometheus text format
    pub fn encode_metrics(&self) -> String {
        let metrics = self.metrics.read().unwrap_or_else(|e| e.into_inner());
        metrics.encode_metrics()
    }
}

impl Default for SharedMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = Metrics::new();
        let output = metrics.encode_metrics();
        assert!(output.contains("balansir_reconciliations_total"));
    }

    #[test]
    fn test_metrics_increments() {
        let metrics = Metrics::new();

        metrics.record_reconciliation();
        metrics.record_reconciliation();
        metrics.record_reconciliation();

        let output = metrics.encode_metrics();
        assert!(output.contains("balansir_reconciliations_total"));
        assert!(output.contains("# TYPE"));
        assert!(
            !output.contains("_total_total"),
            "counter names must not double-suffix: {output}"
        );
    }

    #[test]
    fn test_metrics_gauges() {
        let metrics = Metrics::new();

        metrics.set_active_rules(10);
        metrics.set_desired_rules(15);

        let output = metrics.encode_metrics();
        assert!(output.contains("balansir_active_rules 10"));
        assert!(output.contains("balansir_desired_rules 15"));
    }

    #[test]
    fn test_shared_metrics() {
        let shared = SharedMetrics::new();
        let output = shared.encode_metrics();
        assert!(output.contains("balansir_reconciliations_total"));
    }

    #[test]
    fn test_driver_tier_gauges_encoded() {
        let metrics = Metrics::new();
        metrics.set_driver_tiers([1, 2, 3, 4]);
        metrics.record_driver_lifecycle_transition();
        metrics.record_driver_lifecycle_transition();

        let output = metrics.encode_metrics();
        assert!(output.contains("balansir_drivers{tier=\"healthy\"} 1"));
        assert!(output.contains("balansir_drivers{tier=\"degraded\"} 2"));
        assert!(output.contains("balansir_drivers{tier=\"failing\"} 3"));
        assert!(output.contains("balansir_drivers{tier=\"disabled\"} 4"));
        assert!(output.contains("balansir_driver_lifecycle_transitions_total 2"));
    }

    #[test]
    fn test_health_tier_roundtrip() {
        use crate::types::HealthTier;
        for tier in [
            HealthTier::Healthy,
            HealthTier::Degraded,
            HealthTier::Failing,
            HealthTier::Disabled,
        ] {
            assert_eq!(HealthTier::from_u8(tier.as_u8()), Some(tier));
        }
        assert_eq!(HealthTier::from_u8(9), None);
        assert_eq!(
            HealthTier::from_health_status(&crate::types::HealthStatus::Healthy),
            HealthTier::Healthy
        );
        assert_eq!(
            HealthTier::from_health_status(&crate::types::HealthStatus::Degraded { reason: 1 }),
            HealthTier::Degraded
        );
        assert_eq!(
            HealthTier::from_health_status(&crate::types::HealthStatus::Unhealthy { reason: 2 }),
            HealthTier::Failing
        );
        assert_eq!(
            HealthTier::from_health_status(&crate::types::HealthStatus::Unknown),
            HealthTier::Disabled
        );
    }
}
