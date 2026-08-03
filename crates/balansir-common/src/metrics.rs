use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use std::sync::RwLock;

/// BalanSir metrics collector
pub struct Metrics {
    registry: RwLock<Registry>,

    // Counters
    pub reconciliations_total: Counter,
    pub reconciliation_failures_total: Counter,
    pub drift_items_total: Counter,
    pub executor_operations_total: Counter,
    pub policy_evaluations_total: Counter,

    // Gauges
    pub active_rules: Gauge,
    pub desired_rules: Gauge,
    pub health_status: Gauge,

    // Histograms
    pub reconciliation_duration_seconds: Histogram,
    pub policy_evaluation_duration_micros: Histogram,
    pub executor_operation_duration_micros: Histogram,
}

impl Metrics {
    /// Create new metrics
    pub fn new() -> Self {
        let mut registry = Registry::default();

        let reconciliations_total = Counter::default();
        registry.register(
            "balansir_reconciliations_total",
            "Total number of reconciliation cycles",
            reconciliations_total.clone(),
        );

        let reconciliation_failures_total = Counter::default();
        registry.register(
            "balansir_reconciliation_failures_total",
            "Total number of failed reconciliation cycles",
            reconciliation_failures_total.clone(),
        );

        let drift_items_total = Counter::default();
        registry.register(
            "balansir_drift_items_total",
            "Total number of drift items detected",
            drift_items_total.clone(),
        );

        let executor_operations_total = Counter::default();
        registry.register(
            "balansir_executor_operations_total",
            "Total number of executor operations",
            executor_operations_total.clone(),
        );

        let policy_evaluations_total = Counter::default();
        registry.register(
            "balansir_policy_evaluations_total",
            "Total number of policy evaluations",
            policy_evaluations_total.clone(),
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

        let health_status = Gauge::default();
        registry.register(
            "balansir_health_status",
            "Health status (0=unhealthy, 1=degraded, 2=healthy)",
            health_status.clone(),
        );

        let reconciliation_duration_seconds =
            Histogram::new(exponential_buckets(0.001, 2.0, 10));
        registry.register(
            "balansir_reconciliation_duration_seconds",
            "Duration of reconciliation cycles in seconds",
            reconciliation_duration_seconds.clone(),
        );

        let policy_evaluation_duration_micros =
            Histogram::new(exponential_buckets(1.0, 2.0, 10));
        registry.register(
            "balansir_policy_evaluation_duration_micros",
            "Duration of policy evaluations in microseconds",
            policy_evaluation_duration_micros.clone(),
        );

        let executor_operation_duration_micros =
            Histogram::new(exponential_buckets(10.0, 2.0, 10));
        registry.register(
            "balansir_executor_operation_duration_micros",
            "Duration of executor operations in microseconds",
            executor_operation_duration_micros.clone(),
        );

        Self {
            registry: RwLock::new(registry),
            reconciliations_total,
            reconciliation_failures_total,
            drift_items_total,
            executor_operations_total,
            policy_evaluations_total,
            active_rules,
            desired_rules,
            health_status,
            reconciliation_duration_seconds,
            policy_evaluation_duration_micros,
            executor_operation_duration_micros,
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

    /// Record drift items
    pub fn record_drift(&self, count: u64) {
        self.drift_items_total.inc_by(count);
    }

    /// Record executor operation
    pub fn record_executor_operation(&self) {
        self.executor_operations_total.inc();
    }

    /// Record policy evaluation
    pub fn record_policy_evaluation(&self) {
        self.policy_evaluations_total.inc();
    }

    /// Set active rules gauge
    pub fn set_active_rules(&self, count: i64) {
        self.active_rules.set(count);
    }

    /// Set desired rules gauge
    pub fn set_desired_rules(&self, count: i64) {
        self.desired_rules.set(count);
    }

    /// Set health status gauge
    pub fn set_health_status(&self, status: i64) {
        self.health_status.set(status);
    }

    /// Record reconciliation duration
    pub fn record_reconciliation_duration(&self, seconds: f64) {
        self.reconciliation_duration_seconds.observe(seconds);
    }

    /// Record policy evaluation duration
    pub fn record_policy_evaluation_duration(&self, microseconds: f64) {
        self.policy_evaluation_duration_micros.observe(microseconds);
    }

    /// Record executor operation duration
    pub fn record_executor_operation_duration(&self, microseconds: f64) {
        self.executor_operation_duration_micros.observe(microseconds);
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
    }

    #[test]
    fn test_metrics_gauges() {
        let metrics = Metrics::new();

        metrics.set_active_rules(10);
        metrics.set_desired_rules(15);
        metrics.set_health_status(2);

        let output = metrics.encode_metrics();
        assert!(output.contains("balansir_active_rules 10"));
        assert!(output.contains("balansir_desired_rules 15"));
        assert!(output.contains("balansir_health_status 2"));
    }

    #[test]
    fn test_shared_metrics() {
        let shared = SharedMetrics::new();
        let output = shared.encode_metrics();
        assert!(output.contains("balansir_reconciliations_total"));
    }
}
