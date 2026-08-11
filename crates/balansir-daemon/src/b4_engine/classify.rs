//! B4 connectivity classification (P7.1, ADR-024).
//!
//! A pure, deterministic mapping from host-stack observations to a
//! connectivity class. Classification is a *judgment over observations*, not a
//! packet-inspection feature.

use crate::b4_engine::observe::B4Observation;
use std::time::Duration;

/// How a flow's connectivity is currently classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum B4Class {
    /// Direct path working normally.
    Direct,
    /// Direct path works but is degraded (loss, retrans, high RTT).
    Degraded,
    /// DPI interference suspected (reset/timeout, RST-injection pattern).
    Interfered,
    /// No progress at all (blocked).
    Blocked,
    /// Not enough signal to classify.
    Unknown,
}

/// Deterministic classification over host-stack signals (ADR-024 §2.1).
///
/// Order of precedence is deliberate:
/// 1. A reset/timeout or MTU symptom on a *connected* flow points to
///    interference or an MTU problem, not a total block.
/// 2. A confirmed DNS failure points to interference (resolution path).
/// 3. Heavy retransmission/loss with throughput collapse → degraded.
/// 4. RTT above the degraded threshold → degraded.
/// 5. Otherwise → direct.
pub fn classify(obs: &B4Observation) -> B4Class {
    if !obs.any_signal() {
        return B4Class::Unknown;
    }

    // MTU symptom on a flow that connects is an adaptation trigger, not a
    // total failure: classify as interfered (a DPI/MTU-shaped interruption).
    if obs.mtu_symptom == Some(true) && obs.reset_or_timeout != Some(true) {
        return B4Class::Interfered;
    }

    // A reset/timeout is the strongest DPI/interference signal.
    if obs.reset_or_timeout == Some(true) {
        return B4Class::Interfered;
    }

    // DNS failure means the resolution path is interfered with.
    if obs.dns_ok == Some(false) {
        return B4Class::Interfered;
    }

    // Degradation: heavy retransmissions, high RTT, or throughput collapse.
    let retrans_heavy = obs.retransmissions.is_some_and(|r| r >= 3);
    let high_rtt = obs.rtt.is_some_and(|rtt| rtt >= Duration::from_millis(400));
    let low_throughput = obs.throughput_bps.is_some_and(|b| b < 1_000);
    let degraded = retrans_heavy || high_rtt || low_throughput;

    if degraded {
        return B4Class::Degraded;
    }

    B4Class::Direct
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unknown_when_no_signals() {
        assert_eq!(classify(&B4Observation::default()), B4Class::Unknown);
    }

    #[test]
    fn direct_when_healthy() {
        let obs = B4Observation {
            rtt: Some(Duration::from_millis(20)),
            connect_latency: Some(Duration::from_millis(30)),
            ..Default::default()
        };
        assert_eq!(classify(&obs), B4Class::Direct);
    }

    #[test]
    fn reset_or_timeout_is_interfered() {
        let obs = B4Observation {
            reset_or_timeout: Some(true),
            ..Default::default()
        };
        assert_eq!(classify(&obs), B4Class::Interfered);
    }

    #[test]
    fn dns_failure_is_interfered() {
        let obs = B4Observation {
            dns_ok: Some(false),
            ..Default::default()
        };
        assert_eq!(classify(&obs), B4Class::Interfered);
    }

    #[test]
    fn heavy_retransmissions_are_degraded() {
        let obs = B4Observation {
            retransmissions: Some(7),
            ..Default::default()
        };
        assert_eq!(classify(&obs), B4Class::Degraded);
    }

    #[test]
    fn mtu_symptom_is_interfered() {
        let obs = B4Observation {
            mtu_symptom: Some(true),
            ..Default::default()
        };
        assert_eq!(classify(&obs), B4Class::Interfered);
    }
}
