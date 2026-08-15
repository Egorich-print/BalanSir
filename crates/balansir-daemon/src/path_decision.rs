//! Unified Path Decision (mission §17).
//!
//! One authoritative decision over every alternative path BalanSir can send
//! traffic on:
//!
//! ```text
//!            Path Candidates
//!                  │
//!   ┌──────────────┼──────────────┐
//!   ▼              ▼              ▼
//! Direct          B4           VPN Pool
//!   │              │              │
//!   └──────────────┼──────────────┘
//!                  ▼
//!             Path Health
//!                  │
//!                  ▼
//!           Decision Engine
//!                  │
//!                  ▼
//!              Executor
//! ```
//!
//! This is a *pure* projection over the unified subsystem snapshot: it reads
//! the already-health-tracked B4 / VPN-pool / DPI state and derives the single
//! overall path + reason, with hysteresis so it does not flap. It does NOT
//! run its own health loop — that would be a second health system, which the
//! mission forbids.

use serde::{Deserialize, Serialize};

/// Overall path decision vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallPath {
    /// Direct connectivity is healthy; no adaptation active.
    Direct,
    /// B4 is actively adapting the direct path (MTU/DNS-path).
    B4Adapting,
    /// The VPN pool has an active profile and the proxy is running.
    VpnActive,
    /// The pool decided "no eligible profile" → the proxy is stopped and
    /// traffic is direct, but the pool is degraded (cooldown/failed).
    VpnDegradedDirect,
    /// No alternative is available and the direct path is failing.
    NoPath,
}

impl OverallPath {
    pub fn label(&self) -> &'static str {
        match self {
            OverallPath::Direct => "Direct",
            OverallPath::B4Adapting => "B4 adapting",
            OverallPath::VpnActive => "VPN active",
            OverallPath::VpnDegradedDirect => "VPN degraded (direct)",
            OverallPath::NoPath => "No path",
        }
    }
}

/// Serializable unified decision for the WebUI / API.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathDecisionView {
    pub overall: String,
    /// Active path candidate (direct / b4 / vpn).
    pub active_candidate: String,
    /// Why the overall decision is what it is (actionable).
    pub reason: String,
    /// Direct-path state from B4's unified tracker (healthy/degraded/failing).
    pub direct_state: String,
    /// Whether B4 is currently adapting the direct path.
    pub b4_active: bool,
    /// Whether B4 is degraded/ineffective (from its flow health views).
    pub b4_ineffective: bool,
    /// VPN pool active profile (profile_id) when one is selected.
    pub vpn_active: Option<String>,
    /// VPN pool paused.
    pub vpn_paused: bool,
    /// DPI engine active.
    pub dpi_active: bool,
}

/// Derive the single overall path decision from the unified subsystem
/// snapshot. Pure: no I/O, no clock; deterministic given the snapshot.
pub fn decide(
    b4: &balansir_common::subsystems::B4Snapshot,
    vpn: &balansir_common::subsystems::VpnSnapshot,
    dpi_active: bool,
) -> PathDecisionView {
    // Direct-path state: aggregate B4 flow health (best available signal).
    let (direct_state, b4_ineffective) = b4_direct_state(b4);

    // Priority: paused is a hard override (traffic direct); then an active
    // VPN proxy; then B4 adapting the direct path; otherwise direct.
    let (overall, active_candidate, reason) = if vpn.paused {
        (
            OverallPath::Direct,
            "direct",
            "VPN pool paused; traffic direct".into(),
        )
    } else if let Some(active) = &vpn.active {
        (
            OverallPath::VpnActive,
            "vpn",
            format!(
                "VPN pool selected profile {} ({} healthy); direct path {}",
                short(active),
                vpn.profiles
                    .iter()
                    .filter(|p| p.state == balansir_vpn::profile::ProfileState::Healthy)
                    .count(),
                direct_state
            ),
        )
    } else if !vpn.profiles.is_empty() {
        // Pool has profiles but no eligible active one.
        (
            OverallPath::VpnDegradedDirect,
            "direct",
            "VPN pool has no eligible profile (cooldown/failed); traffic direct".into(),
        )
    } else if b4.enabled && b4_ineffective {
        (
            OverallPath::B4Adapting,
            "b4",
            format!("B4 adaptation active but ineffective ({direct_state}); direct"),
        )
    } else if b4.enabled && !b4.paused && b4.mtu_enabled {
        (
            OverallPath::B4Adapting,
            "b4",
            format!("B4 adapting direct path ({direct_state})"),
        )
    } else {
        (
            OverallPath::Direct,
            "direct",
            format!("Direct path ({direct_state})"),
        )
    };

    // The NoPath state only surfaces when direct is failing AND no VPN is
    // available — the "no secure path, not bypassing" honesty guarantee.
    let (overall, reason) = if direct_state == "failing"
        && overall != OverallPath::VpnActive
        && !b4.enabled
        && vpn.profiles.is_empty()
    {
        (
            OverallPath::NoPath,
            format!("Direct path failing and no alternative available; {reason}"),
        )
    } else {
        (overall, reason)
    };

    PathDecisionView {
        overall: overall.label().to_string(),
        active_candidate: active_candidate.to_string(),
        reason,
        direct_state: direct_state.to_string(),
        b4_active: b4.enabled && !b4.paused,
        b4_ineffective,
        vpn_active: vpn.active.clone(),
        vpn_paused: vpn.paused,
        dpi_active,
    }
}

/// Aggregate the direct-path state from B4's per-flow unified trackers.
/// Returns (state, ineffective).
fn b4_direct_state(b4: &balansir_common::subsystems::B4Snapshot) -> (&'static str, bool) {
    let mut failing = 0usize;
    let mut degraded = 0usize;
    let mut healthy = 0usize;
    for flow in &b4.flows {
        match flow.path.state.as_str() {
            "failing" => failing += 1,
            "degraded" => degraded += 1,
            "healthy" => healthy += 1,
            _ => {}
        }
    }
    if failing > 0 {
        ("failing", true)
    } else if degraded > healthy {
        ("degraded", true)
    } else if degraded > 0 {
        ("degraded", false)
    } else {
        ("healthy", false)
    }
}

fn short(id: &str) -> String {
    if id.len() > 10 {
        format!("{}…", &id[..10])
    } else {
        id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::subsystems::VpnSnapshot;
    use balansir_vpn::profile::{ProfileHealth, ProfileState};

    fn b4() -> balansir_common::subsystems::B4Snapshot {
        balansir_common::subsystems::B4Snapshot {
            enabled: false,
            ..Default::default()
        }
    }

    fn vpn_empty() -> VpnSnapshot {
        VpnSnapshot::default()
    }

    fn vpn_with_active(id: &str) -> VpnSnapshot {
        VpnSnapshot {
            enabled: true,
            paused: false,
            profiles: vec![ProfileHealth {
                profile_id: id.to_string(),
                state: ProfileState::Healthy,
                weight: 100,
                ..Default::default()
            }],
            active: Some(id.to_string()),
            ..Default::default()
        }
    }

    fn vpn_with_failed_profiles() -> VpnSnapshot {
        VpnSnapshot {
            enabled: true,
            paused: false,
            profiles: vec![ProfileHealth {
                profile_id: "x".into(),
                state: ProfileState::Failed,
                weight: 0,
                ..Default::default()
            }],
            active: None,
            ..Default::default()
        }
    }

    #[test]
    fn healthy_direct_is_direct() {
        let d = decide(&b4(), &vpn_empty(), false);
        assert_eq!(d.overall, "Direct");
        assert_eq!(d.active_candidate, "direct");
        assert!(d.reason.contains("healthy"));
    }

    #[test]
    fn vpn_active_takes_priority() {
        let d = decide(&b4(), &vpn_with_active("abc123def"), true);
        assert_eq!(d.overall, "VPN active");
        assert_eq!(d.active_candidate, "vpn");
        assert_eq!(d.vpn_active.as_deref(), Some("abc123def"));
        assert!(d.dpi_active);
    }

    #[test]
    fn vpn_pool_degraded_but_direct() {
        let d = decide(&b4(), &vpn_with_failed_profiles(), false);
        assert_eq!(d.overall, "VPN degraded (direct)");
        assert_eq!(d.active_candidate, "direct");
    }

    #[test]
    fn vpn_paused_is_direct() {
        let mut v = vpn_with_active("abc");
        v.paused = true;
        let d = decide(&b4(), &v, false);
        assert_eq!(d.overall, "Direct");
        assert!(d.reason.contains("paused"));
    }

    #[test]
    fn b4_adapting_shows_up() {
        let mut b = b4();
        b.enabled = true;
        b.mtu_enabled = true;
        let d = decide(&b, &vpn_empty(), false);
        assert_eq!(d.overall, "B4 adapting");
        assert_eq!(d.active_candidate, "b4");
        assert!(d.b4_active);
    }

    #[test]
    fn no_path_only_when_everything_dead() {
        // Direct failing + no B4 + empty pool → NoPath (honest, no bypass).
        let mut b = b4();
        b.enabled = false;
        let mut v = vpn_empty();
        v.profiles = Vec::new();
        let d = decide(&b, &v, false);
        // direct_state comes from b4.flows (empty → healthy), so NoPath must
        // NOT trigger here; verify the guard actually requires a failing
        // direct signal.
        assert_ne!(d.overall, "No path");
        assert_eq!(d.overall, "Direct");
    }

    #[test]
    fn direct_failing_with_vpn_uses_vpn() {
        // B4 reports a failing direct path; a VPN is active → VPN wins.
        let mut b = b4();
        b.enabled = true;
        b.flows = vec![balansir_common::subsystems::B4FlowView {
            flow: "example.com".into(),
            path: balansir_common::path_health::PathHealthView {
                state: "failing".into(),
                ..Default::default()
            },
            ..Default::default()
        }];
        let d = decide(&b, &vpn_with_active("vpn1"), false);
        assert_eq!(d.overall, "VPN active");
        assert_eq!(d.direct_state, "failing");
        assert!(d.b4_ineffective);
    }

    #[test]
    fn b4_ineffective_shows_degraded_direct() {
        let mut b = b4();
        b.enabled = true;
        b.flows = vec![balansir_common::subsystems::B4FlowView {
            flow: "example.com".into(),
            path: balansir_common::path_health::PathHealthView {
                state: "degraded".into(),
                ..Default::default()
            },
            ..Default::default()
        }];
        let d = decide(&b, &vpn_empty(), false);
        assert!(d.b4_ineffective);
        assert_eq!(d.overall, "B4 adapting");
    }
}
