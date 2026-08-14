//! Runtime capability/resource-profile model.
//!
//! Capability detection is **runtime**, not board-name-based (the hardware-
//! aware architecture requirement): BalanSir measures available RAM/CPU and
//! probes kernel features, then maps the result onto a resource profile.
//! Feature availability follows from the profile; the WebUI renders exactly
//! this state (no fake controls for unavailable features).

use serde::{Deserialize, Serialize};

/// Resource profile tiers. Not tied to specific boards — derived from runtime
/// measurements so the same binary behaves correctly on a 256 MB SoC and a
/// 4 GB x86 box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ResourceProfile {
    /// 256–512 MB-class devices. Core policy, firewall, DNS, basic B4, basic
    /// QoS, lean metrics. No ML/BTP, no heavy telemetry.
    Minimal,
    /// ~1 GB and up. Full BalanSir: B4, QoS, Tailscale, Xray, richer telemetry.
    Standard,
    /// 4 GB and up. Advanced telemetry, large histories, multiple paths.
    Performance,
}

impl ResourceProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            ResourceProfile::Minimal => "minimal",
            ResourceProfile::Standard => "standard",
            ResourceProfile::Performance => "performance",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "minimal" => Some(ResourceProfile::Minimal),
            "standard" => Some(ResourceProfile::Standard),
            "performance" => Some(ResourceProfile::Performance),
            _ => None,
        }
    }

    /// Derive a profile from runtime observations.
    pub fn detect(total_ram_mb: u64, cpu_count: usize) -> Self {
        if total_ram_mb >= 4 * 1024 || (total_ram_mb >= 2 * 1024 && cpu_count >= 4) {
            ResourceProfile::Performance
        } else if total_ram_mb >= 768 && cpu_count >= 2 {
            ResourceProfile::Standard
        } else {
            ResourceProfile::Minimal
        }
    }
}

/// Capability flags that vary per profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureSet {
    pub policy_engine: bool,
    pub firewall: bool,
    pub dns: bool,
    pub b4: bool,
    pub qos: bool,
    pub tailscale: bool,
    pub xray: bool,
    pub advanced_telemetry: bool,
    pub ml_btp: bool,
}

impl FeatureSet {
    /// Feature availability for a profile. Everything here is intentionally
    /// conservative: an unavailable feature is *disabled*, never faked.
    pub fn for_profile(profile: ResourceProfile) -> Self {
        match profile {
            ResourceProfile::Minimal => FeatureSet {
                policy_engine: true,
                firewall: true,
                dns: true,
                b4: true,
                qos: true,
                tailscale: false,
                xray: false,
                advanced_telemetry: false,
                ml_btp: false,
            },
            ResourceProfile::Standard => FeatureSet {
                policy_engine: true,
                firewall: true,
                dns: true,
                b4: true,
                qos: true,
                tailscale: true,
                xray: true,
                advanced_telemetry: false,
                ml_btp: false,
            },
            ResourceProfile::Performance => FeatureSet {
                policy_engine: true,
                firewall: true,
                dns: true,
                b4: true,
                qos: true,
                tailscale: true,
                xray: true,
                advanced_telemetry: true,
                ml_btp: true,
            },
        }
    }
}

/// Runtime snapshot used to derive the profile (and rendered in the WebUI).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeSnapshot {
    pub total_ram_mb: u64,
    pub available_ram_mb: u64,
    pub cpu_count: usize,
    pub load_avg: f64,
    pub uptime_seconds: u64,
    pub profile: ResourceProfile,
    pub features: FeatureSet,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_detection_boundaries() {
        assert_eq!(ResourceProfile::detect(256, 1), ResourceProfile::Minimal);
        assert_eq!(ResourceProfile::detect(512, 2), ResourceProfile::Minimal);
        assert_eq!(ResourceProfile::detect(1024, 2), ResourceProfile::Standard);
        assert_eq!(
            ResourceProfile::detect(4096, 2),
            ResourceProfile::Performance
        );
        assert_eq!(
            ResourceProfile::detect(2048, 4),
            ResourceProfile::Performance
        );
        assert_eq!(
            ResourceProfile::detect(4096, 1),
            ResourceProfile::Performance
        );
    }

    #[test]
    fn feature_set_is_conservative() {
        let minimal = FeatureSet::for_profile(ResourceProfile::Minimal);
        assert!(minimal.policy_engine && minimal.firewall && minimal.dns);
        assert!(!minimal.xray && !minimal.advanced_telemetry && !minimal.ml_btp);

        let perf = FeatureSet::for_profile(ResourceProfile::Performance);
        assert!(perf.advanced_telemetry && perf.ml_btp);
    }

    #[test]
    fn profile_roundtrip() {
        for p in [
            ResourceProfile::Minimal,
            ResourceProfile::Standard,
            ResourceProfile::Performance,
        ] {
            assert_eq!(ResourceProfile::from_str(p.as_str()), Some(p));
        }
    }
}
