//! B4 observation model (P7.1, ADR-024).
//!
//! Observations are **host-stack-only** (no MITM, no payload reads): TCP_INFO
//! signals, connect error classes, and the DNS plane. The `B4Observer` trait
//! is the boundary through which the runtime loop receives signals; the state
//! machine never performs I/O itself.

use std::time::Duration;

/// Host-stack observation for a flow (all fields optional — absent = unknown).
///
/// These are the *only* signals B4 may use (ADR-024 §4): everything else would
/// require MITM or payload inspection and is out of scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct B4Observation {
    /// TCP connect latency (from `connect()` timing / host stack).
    pub connect_latency: Option<Duration>,
    /// Observed RTT (TCP_INFO `tcpi_rtt`).
    pub rtt: Option<Duration>,
    /// RTT variance (TCP_INFO `tcpi_rttvar`).
    pub rtt_var: Option<Duration>,
    /// Retransmission count growth (TCP_INFO).
    pub retransmissions: Option<u32>,
    /// Throughput in bytes/sec (host-side counters).
    pub throughput_bps: Option<u64>,
    /// Whether the flow's DNS resolution succeeded (DNS plane).
    pub dns_ok: Option<bool>,
    /// Whether a connection reset / timeout was observed.
    pub reset_or_timeout: Option<bool>,
    /// Whether an MTU symptom (`EMSGSIZE`, fragmentation) was observed.
    pub mtu_symptom: Option<bool>,
}

impl B4Observation {
    pub fn any_signal(&self) -> bool {
        self.connect_latency.is_some()
            || self.rtt.is_some()
            || self.rtt_var.is_some()
            || self.retransmissions.is_some()
            || self.throughput_bps.is_some()
            || self.dns_ok.is_some()
            || self.reset_or_timeout.is_some()
            || self.mtu_symptom.is_some()
    }
}

/// Boundary through which the engine receives host-stack observations.
///
/// Implementations are injected; the engine treats missing signals as unknown.
/// A real implementation reads TCP_INFO/DNS/errors; tests use fakes.
#[async_trait::async_trait]
pub trait B4Observer: Send + Sync {
    /// Observe the current state of a flow (identified by its domain / key).
    async fn observe(&self, flow_key: &str) -> B4Observation;
}

/// Observer that reports no signals (unknown). Used when no host-stack source
/// is wired, so the engine degrades to policy-only behavior honestly.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopObserver;

#[async_trait::async_trait]
impl B4Observer for NoopObserver {
    async fn observe(&self, _flow_key: &str) -> B4Observation {
        B4Observation::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_observation_has_no_signals() {
        assert!(!B4Observation::default().any_signal());
    }
}
