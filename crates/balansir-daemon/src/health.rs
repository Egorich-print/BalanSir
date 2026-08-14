//! Unified path-health model with hysteresis (mission: "is my network OK,
//! why not, what is BalanSir doing").
//!
//! Each tracked path (Direct, B4, Xray, Tailscale) feeds binary samples —
//! "reachable / healthy" or not — into a `PathHealthTracker`. The tracker
//! applies hysteresis so short blips don't flap the UI state: N consecutive
//! unhealthy samples degrade the path, M consecutive healthy samples recover
//! it. The daemon exposes one human-facing state per path plus the raw sample
//! series, so the WebUI can say *why*.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

/// Stable, human-facing health state of a single path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathState {
    /// Healthy: last M samples all good.
    Healthy,
    /// Degrading: this sample was bad but we haven't hit the degrade threshold.
    Degrading,
    /// Degraded: N consecutive bad samples; something is wrong.
    Degraded,
    /// Recovering: a good sample after degradation but not yet cleared.
    Recovering,
    /// Not enabled / no data.
    Unknown,
}

impl PathState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PathState::Healthy => "healthy",
            PathState::Degrading => "degrading",
            PathState::Degraded => "degraded",
            PathState::Recovering => "recovering",
            PathState::Unknown => "unknown",
        }
    }
}

/// Per-path live health report exposed to the WebUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathHealth {
    pub path: String,
    pub state: PathState,
    /// Why: short free-text reason for the current state (e.g. "3/3 probes
    /// timed out", "mtu mismatch", "process not running").
    pub reason: String,
    /// Recent binary samples, oldest first.
    pub samples: Vec<bool>,
    /// Sample history capacity.
    pub window: usize,
    pub last_change_ts: u64,
}

/// Tracks one path's health with hysteresis.
pub struct PathHealthTracker {
    path: String,
    degrade_after: usize,
    recover_after: usize,
    samples: VecDeque<bool>,
    state: PathState,
    consecutive_bad: usize,
    consecutive_good: usize,
    last_change_ts: u64,
}

impl PathHealthTracker {
    pub fn new(path: &str, window: usize, degrade_after: usize, recover_after: usize) -> Self {
        Self {
            path: path.to_string(),
            degrade_after: degrade_after.max(1),
            recover_after: recover_after.max(1),
            samples: VecDeque::with_capacity(window),
            state: PathState::Unknown,
            consecutive_bad: 0,
            consecutive_good: 0,
            last_change_ts: now_secs(),
        }
    }

    /// Record one health sample (`ok` = reachable) and advance the state
    /// machine with hysteresis. Returns the new state.
    pub fn observe(&mut self, ok: bool) -> PathState {
        if self.samples.len() == self.samples.capacity() {
            self.samples.pop_front();
        }
        self.samples.push_back(ok);

        match self.state {
            PathState::Unknown | PathState::Recovering => {
                if ok {
                    self.consecutive_good += 1;
                    self.consecutive_bad = 0;
                    if self.consecutive_good >= self.recover_after {
                        self.transition(PathState::Healthy);
                    }
                } else {
                    self.consecutive_good = 0;
                    self.consecutive_bad += 1;
                    if self.state == PathState::Unknown
                        && self.consecutive_bad >= self.degrade_after
                    {
                        self.transition(PathState::Degraded);
                    } else if self.state == PathState::Unknown {
                        self.transition(PathState::Degrading);
                    } else {
                        // Recovering + bad sample: snap back to degraded.
                        self.transition(PathState::Degraded);
                    }
                }
            }
            PathState::Healthy => {
                if ok {
                    self.consecutive_good += 1;
                    self.consecutive_bad = 0;
                } else {
                    self.consecutive_good = 0;
                    self.consecutive_bad += 1;
                    if self.consecutive_bad >= self.degrade_after {
                        self.transition(PathState::Degraded);
                    } else {
                        self.transition(PathState::Degrading);
                    }
                }
            }
            PathState::Degrading => {
                if ok {
                    self.consecutive_good += 1;
                    self.consecutive_bad = 0;
                    if self.consecutive_good >= self.recover_after {
                        self.transition(PathState::Healthy);
                    } else {
                        self.transition(PathState::Recovering);
                    }
                } else {
                    self.consecutive_good = 0;
                    self.consecutive_bad += 1;
                    if self.consecutive_bad >= self.degrade_after {
                        self.transition(PathState::Degraded);
                    }
                }
            }
            PathState::Degraded => {
                if ok {
                    self.consecutive_bad = 0;
                    self.consecutive_good += 1;
                    self.transition(PathState::Recovering);
                } else {
                    self.consecutive_good = 0;
                    self.consecutive_bad += 1;
                }
            }
        }
        self.state
    }

    fn transition(&mut self, next: PathState) {
        if self.state != next {
            self.state = next;
            self.last_change_ts = now_secs();
        }
    }

    /// Current state (without recording a sample).
    pub fn state(&self) -> PathState {
        self.state
    }

    /// Report for the WebUI.
    pub fn report(&self) -> PathHealth {
        let reason = match self.state {
            PathState::Healthy => "probes passing".to_string(),
            PathState::Degrading | PathState::Degraded => format!(
                "{}/{} recent probes failed",
                self.consecutive_bad,
                self.samples.len()
            ),
            PathState::Recovering => {
                format!("recovering after {} bad probe(s)", self.consecutive_bad)
            }
            PathState::Unknown => "no data yet".to_string(),
        };
        PathHealth {
            path: self.path.clone(),
            state: self.state,
            reason,
            samples: self.samples.iter().copied().collect(),
            window: self.samples.capacity(),
            last_change_ts: self.last_change_ts,
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Probe reachability with a single ICMP echo (used for the "direct" path).
/// Returns false on timeout / missing `ping` / permission denied. Never panics.
pub async fn probe_ping(host: &str) -> bool {
    let Some(bin) = balansir_common::paths::resolve_bin("ping") else {
        return false;
    };
    let host = host.to_string();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(bin)
            .args(["-c", "1", "-W", "3", &host])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_requires_recover_after_good_from_unknown() {
        let mut t = PathHealthTracker::new("direct", 16, 3, 3);
        assert_eq!(t.observe(true), PathState::Unknown);
        assert_eq!(t.observe(true), PathState::Unknown);
        assert_eq!(t.observe(true), PathState::Healthy);
    }

    #[test]
    fn degrades_after_n_bad_and_recovers_after_m_good() {
        let mut t = PathHealthTracker::new("direct", 16, 3, 3);
        for _ in 0..3 {
            let _ = t.observe(true);
        }
        assert_eq!(t.state(), PathState::Healthy);

        // One blip: Degrading, not Degraded.
        assert_eq!(t.observe(false), PathState::Degrading);
        assert_eq!(t.observe(false), PathState::Degrading);
        assert_eq!(t.observe(false), PathState::Degraded);

        // Recovery needs 3 good samples.
        assert_eq!(t.observe(true), PathState::Recovering);
        assert_eq!(t.observe(true), PathState::Recovering);
        assert_eq!(t.observe(true), PathState::Healthy);
    }

    #[test]
    fn degraded_snaps_back_on_bad_during_recovery() {
        let mut t = PathHealthTracker::new("xray", 16, 2, 2);
        for _ in 0..2 {
            let _ = t.observe(true);
        }
        assert_eq!(t.state(), PathState::Healthy);
        for _ in 0..2 {
            let _ = t.observe(false);
        }
        assert_eq!(t.state(), PathState::Degraded);
        assert_eq!(t.observe(true), PathState::Recovering);
        // Bad sample during recovery -> back to Degraded.
        assert_eq!(t.observe(false), PathState::Degraded);
    }

    #[test]
    fn report_carries_samples_and_reason() {
        let mut t = PathHealthTracker::new("b4", 8, 2, 2);
        for _ in 0..2 {
            let _ = t.observe(true);
        }
        for _ in 0..2 {
            let _ = t.observe(false);
        }
        let r = t.report();
        assert_eq!(r.state, PathState::Degraded);
        assert!(r.reason.contains("failed"));
        assert_eq!(r.samples.len(), 4);
        assert_eq!(r.window, 8);
    }
}
