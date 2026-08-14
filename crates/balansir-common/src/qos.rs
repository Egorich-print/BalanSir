//! QoS / traffic-shaping model (unified across daemon, executor, API and UI).
//!
//! This is the single source of truth for shaping intent and reported state.
//! The daemon owns the *desired* shaping configuration; the privileged
//! executor applies it to the kernel (qdisc/classes) and reports the *applied*
//! state plus live queue statistics. Reconciliation converges the two (P4.1
//! ownership), exactly like nftables rules and B4 path MTUs.
//!
//! Capability detection is part of the contract: a kernel that lacks CAKE
//! must be reported honestly, and the daemon must pick a safe fallback
//! (fq_codel) or refuse rather than pretend shaping happened.

use serde::{Deserialize, Serialize};

/// Traffic-control disciplines BalanSir can request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QdiscKind {
    /// fq_codel — per-flow fair queueing with CoDel AQM. Widely available.
    FqCodel,
    /// CAKE — Common Applications Kept Enhanced. Preferred when present.
    Cake,
    /// Ingress qdisc attachment (stats + policer hook). No shaping by itself.
    Ingress,
}

impl QdiscKind {
    /// Kernel kind name used in `TCA_KIND`.
    pub fn as_str(self) -> &'static str {
        match self {
            QdiscKind::FqCodel => "fq_codel",
            QdiscKind::Cake => "cake",
            QdiscKind::Ingress => "ingress",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "fq_codel" => Some(QdiscKind::FqCodel),
            "cake" => Some(QdiscKind::Cake),
            "ingress" => Some(QdiscKind::Ingress),
            _ => None,
        }
    }
}

/// Which direction of traffic a shaping policy applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QosDirection {
    /// Outbound (interface TX). Root qdisc.
    Egress,
    /// Inbound (interface RX). Ingress qdisc (stats/policing), plus IFB-based
    /// shaping when the kernel supports it.
    Ingress,
}

impl QosDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            QosDirection::Egress => "egress",
            QosDirection::Ingress => "ingress",
        }
    }
}

/// A shaping class under the root qdisc. For CAKE this maps to
/// per-class bandwidth (split-gate); for fq_codel classes are informational.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosClass {
    /// Stable class id (used for classid/prio).
    pub id: u32,
    pub name: String,
    /// Per-class rate cap in bits/second. `None` = inherit the parent rate.
    pub bandwidth_bps: Option<u64>,
    /// Priority hint 0..7 (lowest = highest priority).
    pub priority: u8,
}

/// Desired shaping policy for one interface (daemon-side intent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosConfig {
    pub interface: String,
    pub direction: QosDirection,
    pub kind: QdiscKind,
    /// Overall shaping rate in bits/second (egress). `None` = no hard cap,
    /// AQM still applies.
    pub bandwidth_bps: Option<u64>,
    /// AQM latency target in milliseconds (CoDel target / CAKE target).
    pub latency_target_ms: Option<u64>,
    /// Per-packet overhead in bytes (CAKE overhead, may be negative for e.g.
    /// 802.1Q accounting on the wire).
    pub overhead_bytes: Option<i32>,
    /// Enable ECN.
    pub ecn: bool,
    /// Wash: clear the DiffServ field (CAKE `wash`).
    pub wash: bool,
    /// Queue memory limit in bytes (fq_codel memory_limit / CAKE memory).
    pub memory_limit_bytes: Option<u64>,
    pub classes: Vec<QosClass>,
    /// Stable identity comment for applied qdiscs (`balansir:<interface>`).
    pub comment: String,
}

impl QosConfig {
    /// The canonical BalanSir qdisc identity comment.
    pub fn identity(interface: &str) -> String {
        format!("balansir:qos:{interface}")
    }
}

/// Live queue statistics reported by the kernel for one qdisc.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QdiscStats {
    pub bytes: u64,
    pub packets: u64,
    pub drops: u64,
    pub overlimits: u64,
    pub qlen: u64,
    pub backlog_bytes: u64,
    pub backlog_packets: u64,
    pub bps: u64,
    pub pps: u64,
}

/// Applied qdisc state as reported by the executor (non-authoritative, for
/// reconciliation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedQdisc {
    pub interface: String,
    pub index: i32,
    pub handle: String,
    pub parent: String,
    pub kind: Option<String>,
    pub our_identity: bool,
    pub stats: Option<QdiscStats>,
}

/// Kernel capabilities relevant to shaping, probed at runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosCapabilities {
    pub cake: bool,
    pub fq_codel: bool,
    pub ingress: bool,
    pub htb: bool,
    pub netem: bool,
    /// Whether egress shaping (a real root qdisc) is possible.
    pub egress_shaping: bool,
    /// Whether ingress shaping can actually cap bandwidth (IFB present).
    pub ingress_shaping: bool,
}

impl QosCapabilities {
    /// A fully-unavailable capability set (used when probing fails).
    pub fn unavailable() -> Self {
        Self::default()
    }

    /// Pick the best supported qdisc kind for a direction.
    pub fn best_egress_kind(&self) -> Option<QdiscKind> {
        if self.cake {
            Some(QdiscKind::Cake)
        } else if self.fq_codel {
            Some(QdiscKind::FqCodel)
        } else {
            None
        }
    }
}

/// One shaping operation over the executor boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QosOp {
    Apply(QosConfig),
    Remove { interface: String },
}

/// Outcome of applying/removing shaping on the executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QosResult {
    pub op: String,
    pub interface: String,
    pub ok: bool,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qdisc_kind_roundtrip() {
        for kind in [QdiscKind::FqCodel, QdiscKind::Cake, QdiscKind::Ingress] {
            assert_eq!(QdiscKind::from_str(kind.as_str()), Some(kind));
        }
        assert_eq!(QdiscKind::from_str("htb"), None);
    }

    #[test]
    fn identity_comment_is_stable() {
        assert_eq!(
            QosConfig::identity("wan0"),
            "balansir:qos:wan0"
        );
    }

    #[test]
    fn capabilities_pick_best_egress_kind() {
        let caps = QosCapabilities {
            cake: true,
            fq_codel: true,
            ..Default::default()
        };
        assert_eq!(caps.best_egress_kind(), Some(QdiscKind::Cake));

        let caps = QosCapabilities {
            cake: false,
            fq_codel: true,
            ..Default::default()
        };
        assert_eq!(caps.best_egress_kind(), Some(QdiscKind::FqCodel));

        assert_eq!(
            QosCapabilities::unavailable().best_egress_kind(),
            None
        );
    }

    #[test]
    fn config_defaults_serialize() {
        let cfg = QosConfig {
            interface: "eth0".into(),
            direction: QosDirection::Egress,
            kind: QdiscKind::FqCodel,
            bandwidth_bps: Some(100_000_000),
            latency_target_ms: Some(20),
            overhead_bytes: None,
            ecn: true,
            wash: false,
            memory_limit_bytes: None,
            classes: vec![QosClass {
                id: 1,
                name: "bulk".into(),
                bandwidth_bps: None,
                priority: 4,
            }],
            comment: QosConfig::identity("eth0"),
        };
        let bytes = postcard::to_allocvec(&cfg).unwrap();
        let back: QosConfig = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, cfg);
    }
}
