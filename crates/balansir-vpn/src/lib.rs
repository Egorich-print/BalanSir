//! BalanSir VPN pool — health-aware alternative-path management.
//!
//! A pool of validated VPN endpoint profiles with deterministic, explainable
//! selection: weighted by health (unified `PathHealth`), cooldown-aware,
//! recovery with ramp-up, flow stickiness, and capacity-aware load
//! distribution. This is the decision engine the Xray manager consumes — the
//! Xray manager no longer decides priority/health on its own.

pub mod importer;
pub mod pool;
pub mod profile;
pub mod uri;

pub use importer::{import_subscription, ImportResult, RejectedProfile};
pub use pool::{PoolConfig, PoolSnapshot, SelectionDecision, VpnPool};
pub use profile::{ProfileHealth, ProfileState, Protocol, Security, Transport, VpnProfile};

/// Path to the manual VPN profiles file (persisted across flashes).
pub const MANUAL_PROFILES_PATH: &str = "/persistent/balansir/manual-vpn.txt";

/// Read manual VLESS URIs from the persistent store.
pub fn read_manual_profiles() -> String {
    std::fs::read_to_string(MANUAL_PROFILES_PATH).unwrap_or_default()
}

/// Append a VLESS URI to the manual profiles file. Dedup by exact line match.
pub fn append_manual_profile(uri: &str) -> Result<(), String> {
    let uri = uri.trim();
    if !uri.starts_with("vless://") {
        return Err("only vless:// URIs are supported".into());
    }
    if uri.len() > 4096 {
        return Err("URI too long (max 4096 bytes)".into());
    }
    if let Some(parent) = std::path::Path::new(MANUAL_PROFILES_PATH).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let existing = read_manual_profiles();
    if existing.lines().any(|l| l.trim() == uri) {
        return Ok(());
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(MANUAL_PROFILES_PATH)
        .map_err(|e| format!("open {MANUAL_PROFILES_PATH}: {e}"))?;
    writeln!(f, "{uri}").map_err(|e| format!("write {MANUAL_PROFILES_PATH}: {e}"))?;
    Ok(())
}

/// Remove lines from the manual profiles file whose content matches `needle`.
pub fn remove_manual_profile(needle: &str) -> Result<bool, String> {
    let existing = read_manual_profiles();
    if existing.is_empty() {
        return Ok(false);
    }
    let lines: Vec<&str> = existing.lines().filter(|l| !l.contains(needle)).collect();
    let removed = lines.len() < existing.lines().count();
    if removed {
        std::fs::write(MANUAL_PROFILES_PATH, lines.join("\n") + "\n")
            .map_err(|e| format!("write: {e}"))?;
    }
    Ok(removed)
}
