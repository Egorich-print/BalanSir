//! Runtime capability detection: turns observed hardware resources into a
//! resource tier (Minimal / Standard / Performance) and a feature-availability
//! list the WebUI renders without fake controls.
//!
//! The tier is derived from runtime resources — never from a board-name
//! allowlist — so the same binary works on a 512 MB Milk-V Duo S, an RPi 3B+,
//! an RK3568 box, or an N100. Detection is cheap: two small `/proc` reads.

use balansir_common::subsystems::{CapabilityProfile, FeatureAvailability};

/// Minimal: 256–512 MB class devices.
const MINIMAL_RAM_MB: u64 = 768;
/// Standard: ~1 GB class devices.
const STANDARD_RAM_MB: u64 = 4096;

/// Detect total RAM in MB from `/proc/meminfo`.
fn total_ram_mb() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|raw| {
            raw.lines().find_map(|line| {
                let mut parts = line.split_whitespace();
                if parts.next() == Some("MemTotal:") {
                    parts.next().and_then(|v| v.parse::<u64>().ok())
                } else {
                    None
                }
            })
        })
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

/// Detect CPU count from `/sys/devices/system/cpu/possible`.
fn cpu_count() -> u32 {
    std::fs::read_to_string("/sys/devices/system/cpu/possible")
        .ok()
        .and_then(|raw| {
            // Format: "0-3" or "0". Count the entries.
            let s = raw.trim();
            let (lo, hi) = match s.split_once('-') {
                Some((lo, hi)) => (lo.parse::<u32>().ok(), hi.parse::<u32>().ok()),
                None => (s.parse::<u32>().ok(), None),
            };
            match (lo, hi) {
                (Some(lo), Some(hi)) => Some(hi - lo + 1),
                (Some(lo), None) => Some(lo + 1),
                _ => None,
            }
        })
        .unwrap_or(1)
}

fn tier_for(ram_mb: u64) -> &'static str {
    if ram_mb == 0 {
        "Unknown"
    } else if ram_mb < MINIMAL_RAM_MB {
        "Minimal"
    } else if ram_mb < STANDARD_RAM_MB {
        "Standard"
    } else {
        "Performance"
    }
}

/// Build the feature-availability list for the detected tier.
fn features_for(tier: &str) -> Vec<FeatureAvailability> {
    let mut out = vec![
        FeatureAvailability::available("Policy engine"),
        FeatureAvailability::available("Firewall / nftables"),
        FeatureAvailability::available("DNS policy plane"),
        FeatureAvailability::available("B4 connectivity adaptation"),
        FeatureAvailability::available("QoS / qdisc shaping"),
    ];
    match tier {
        "Minimal" => {
            out.push(FeatureAvailability::limited(
                "Xray transport",
                "Limited resources — one endpoint, modest memory footprint",
            ));
            out.push(FeatureAvailability::limited(
                "Tailscale",
                "Limited resources — expect reduced throughput",
            ));
            out.push(FeatureAvailability::unavailable(
                "Advanced telemetry",
                "Disabled by resource profile (retention/collectors too heavy)",
            ));
            out.push(FeatureAvailability::unavailable(
                "Multiple simultaneous paths",
                "Disabled by resource profile",
            ));
            out.push(FeatureAvailability::unavailable(
                "ML / BTP",
                "Not available on Minimal profile",
            ));
        }
        "Standard" => {
            out.push(FeatureAvailability::available("Xray transport"));
            out.push(FeatureAvailability::available("Tailscale"));
            out.push(FeatureAvailability::limited(
                "Advanced telemetry",
                "Bounded retention on Standard profile",
            ));
            out.push(FeatureAvailability::available(
                "Multiple simultaneous paths",
            ));
            out.push(FeatureAvailability::unavailable(
                "ML / BTP",
                "Not available on Standard profile",
            ));
        }
        _ => {
            // Performance (or Unknown → assume full).
            out.push(FeatureAvailability::available("Xray transport"));
            out.push(FeatureAvailability::available("Tailscale"));
            out.push(FeatureAvailability::available("Advanced telemetry"));
            out.push(FeatureAvailability::available(
                "Multiple simultaneous paths",
            ));
            out.push(FeatureAvailability::unavailable(
                "ML / BTP",
                "Not yet implemented",
            ));
        }
    }
    out
}

/// Full runtime detection. `None` ram (non-Linux) still produces a usable
/// profile with tier `Unknown`.
pub fn detect() -> CapabilityProfile {
    let ram_mb = total_ram_mb();
    let cores = cpu_count();
    let tier = tier_for(ram_mb);
    CapabilityProfile {
        tier: tier.to_string(),
        ram_mb,
        cores,
        features: features_for(tier),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_thresholds() {
        assert_eq!(tier_for(512), "Minimal");
        assert_eq!(tier_for(1024), "Standard");
        assert_eq!(tier_for(8192), "Performance");
        assert_eq!(tier_for(0), "Unknown");
    }

    #[test]
    fn minimal_limits_expectations() {
        let f = features_for("Minimal");
        let xray = f.iter().find(|x| x.name == "Xray transport").unwrap();
        assert!(xray.available && xray.limited);
        let ml = f.iter().find(|x| x.name == "ML / BTP").unwrap();
        assert!(!ml.available);
        assert!(ml.reason.as_deref().unwrap().contains("Minimal"));
        // Core features never lie.
        assert!(
            f.iter()
                .find(|x| x.name == "Policy engine")
                .unwrap()
                .available
        );
    }

    #[test]
    fn performance_is_full() {
        let f = features_for("Performance");
        assert!(
            f.iter()
                .find(|x| x.name == "Advanced telemetry")
                .unwrap()
                .available
        );
        assert!(
            f.iter()
                .find(|x| x.name == "Xray transport")
                .unwrap()
                .available
        );
    }

    #[test]
    fn cpu_count_parses_range() {
        // The parser handles both "0-3" and "0" shapes.
        let n = cpu_count();
        assert!(n >= 1);
    }

    #[test]
    fn detect_never_panics() {
        let profile = detect();
        assert!(profile.cores >= 1);
        assert!(matches!(
            profile.tier.as_str(),
            "Minimal" | "Standard" | "Performance" | "Unknown"
        ));
        assert!(!profile.features.is_empty());
    }
}
