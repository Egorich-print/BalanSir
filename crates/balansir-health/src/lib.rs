//! Unified path health model (mission §9).
//!
//! Shared health semantics for every path a packet can take: Direct, B4,
//! Xray, and future transports. One vocabulary, one set of thresholds, and
//! the same hysteresis rules, so "why did BalanSir switch paths?" always has
//! the same answer shape regardless of the transport underneath.
//!
//! Design:
//! - **EMA smoothing** for latency, variance and loss so single-sample blips
//!   do not move the state machine.
//! - **Hysteresis** via `enter_degraded` / `exit_degraded` counters: it takes
//!   several *consecutive* degraded samples to enter a bad state and several
//!   consecutive good samples to leave it.
//! - **Anti-flapping cooldown**: improving transitions (Failing/Degraded →
//!   Healthy) are gated by a minimum interval. Worsening transitions are
//!   never gated — detecting that a path got worse must never be delayed.
//!
//! The tracker is pure and clock-dependent only for the cooldown; it holds no
//! connections and performs no I/O.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Shared path state vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathState {
    /// Not enough samples yet to judge the path.
    Unknown,
    /// Within configured thresholds.
    Healthy,
    /// Sustained latency/loss above threshold; connectivity still OK.
    Degraded,
    /// Sustained connectivity failures; the path should not carry traffic.
    Failing,
}

impl PathState {
    /// Human label matching the WebUI status vocabulary.
    pub fn label(&self) -> &'static str {
        match self {
            PathState::Unknown => "Unknown",
            PathState::Healthy => "Healthy",
            PathState::Degraded => "Degraded",
            PathState::Failing => "Failing",
        }
    }
}

/// Tunables for one path tracker. All fields are bounded so a malformed
/// config cannot spin the CPU or hold history forever.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PathHealthConfig {
    /// EMA-smoothed latency (ms) above which the path counts as degraded.
    pub latency_threshold_ms: f64,
    /// EMA-smoothed packet loss (%) above which the path counts as degraded.
    pub loss_threshold_pct: f64,
    /// Consecutive degraded samples needed to enter Degraded/Failing.
    pub enter_degraded: u32,
    /// Consecutive healthy samples needed to leave Degraded/Failing.
    pub exit_degraded: u32,
    /// Minimum interval between improving transitions (anti-flapping).
    pub cooldown: Duration,
    /// EMA smoothing factor for latency/variance/loss, `0 < alpha <= 1`.
    pub alpha: f64,
}

impl Default for PathHealthConfig {
    fn default() -> Self {
        Self {
            latency_threshold_ms: 150.0,
            loss_threshold_pct: 5.0,
            enter_degraded: 2,
            exit_degraded: 3,
            cooldown: Duration::from_secs(10),
            alpha: 0.3,
        }
    }
}

/// One probe sample for a path.
#[derive(Debug, Clone, Copy)]
pub struct PathSample {
    /// Measured latency in ms (None when the probe could not time a round
    /// trip, e.g. no traffic on the path yet).
    pub latency_ms: Option<f64>,
    /// Estimated packet loss in percent (None when not measurable).
    pub loss_pct: Option<f64>,
    /// Connectivity success. `false` means the probe failed outright
    /// (timeout/reset) — much stronger evidence than a slow RTT.
    pub reachable: bool,
    /// Explicit evidence of degradation that has no clean numeric form (e.g.
    /// heavy retransmits with a low RTT, throughput collapse). Lets consumers
    /// feed qualitive signals without inventing fake latency/loss numbers.
    pub degraded_evidence: bool,
}

impl PathSample {
    pub fn healthy() -> Self {
        Self {
            latency_ms: None,
            loss_pct: None,
            reachable: true,
            degraded_evidence: false,
        }
    }

    pub fn failure() -> Self {
        Self {
            latency_ms: None,
            loss_pct: None,
            reachable: false,
            degraded_evidence: false,
        }
    }
}

/// A state transition returned by [`PathHealth::observe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathTransition {
    EnteredDegraded,
    EnteredFailing,
    Recovered,
}

/// Serializable view for CLI / REST / SSE / Tauri.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathHealthView {
    /// Lowercase [`PathState::label`]: "unknown" | "healthy" | "degraded" | "failing".
    pub state: String,
    pub latency_ms: Option<f64>,
    pub variance_ms: Option<f64>,
    pub loss_pct: Option<f64>,
    pub samples: u64,
    /// Cumulative connectivity failures over the tracker's lifetime.
    pub failures: u64,
    /// Consecutive degraded samples (drives failover / UI badge).
    pub consecutive_failures: u32,
    /// Human-readable "why" lines, e.g. `RTT 184 ms exceeds 150 ms threshold`.
    pub reasons: Vec<String>,
}

/// Per-path health tracker with EMA smoothing, hysteresis and anti-flapping.
#[derive(Debug, Clone)]
pub struct PathHealth {
    config: PathHealthConfig,
    state: PathState,
    latency_ms: f64,
    variance_ms: f64,
    loss_pct: f64,
    samples: u64,
    consecutive_bad: u32,
    consecutive_good: u32,
    failures: u64,
    last_transition: Option<Instant>,
}

impl PathHealth {
    pub fn new(config: PathHealthConfig) -> Self {
        Self {
            config,
            state: PathState::Unknown,
            latency_ms: 0.0,
            variance_ms: 0.0,
            loss_pct: 0.0,
            samples: 0,
            consecutive_bad: 0,
            consecutive_good: 0,
            failures: 0,
            last_transition: None,
        }
    }

    pub fn state(&self) -> PathState {
        self.state
    }

    /// Number of consecutive degraded samples (drives failover).
    pub fn consecutive_bad(&self) -> u32 {
        self.consecutive_bad
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Forget everything and go back to Unknown (used on manual switch).
    pub fn reset(&mut self) {
        *self = Self::new(self.config);
    }

    /// Feed one probe sample; returns the transition taken, if any.
    pub fn observe(&mut self, sample: PathSample) -> Option<PathTransition> {
        self.samples = self.samples.saturating_add(1);
        self.update_ema(sample);

        let degraded = !sample.reachable
            || sample.degraded_evidence
            || self.config.latency_threshold_ms.is_finite()
                && sample
                    .latency_ms
                    .is_some_and(|l| l > self.config.latency_threshold_ms)
            || self.config.loss_threshold_pct.is_finite()
                && sample
                    .loss_pct
                    .is_some_and(|l| l > self.config.loss_threshold_pct);

        if degraded {
            self.consecutive_bad = self.consecutive_bad.saturating_add(1);
            self.consecutive_good = 0;
        } else {
            self.consecutive_good = self.consecutive_good.saturating_add(1);
            self.consecutive_bad = 0;
        }
        if !sample.reachable {
            self.failures = self.failures.saturating_add(1);
        }

        let target = if self.consecutive_bad >= self.config.enter_degraded {
            if !sample.reachable {
                PathState::Failing
            } else {
                PathState::Degraded
            }
        } else {
            PathState::Healthy
        };

        if target == self.state {
            return None;
        }

        // Worsening transitions are immediate; improving transitions need
        // sustained good samples and must respect the anti-flapping cooldown.
        let rank = |s: PathState| match s {
            PathState::Unknown => 0,
            PathState::Healthy => 1,
            PathState::Degraded => 2,
            PathState::Failing => 3,
        };
        let improving = rank(target) < rank(self.state);
        if improving {
            if self.consecutive_good < self.config.exit_degraded {
                return None;
            }
            if let Some(last) = self.last_transition {
                if last.elapsed() < self.config.cooldown {
                    return None;
                }
            }
        }

        let prev = self.state;
        self.state = target;
        self.last_transition = Some(Instant::now());
        match (prev, target) {
            (PathState::Healthy, PathState::Degraded) => Some(PathTransition::EnteredDegraded),
            (PathState::Healthy | PathState::Degraded, PathState::Failing) => {
                Some(PathTransition::EnteredFailing)
            }
            (PathState::Failing | PathState::Degraded, PathState::Healthy) => {
                Some(PathTransition::Recovered)
            }
            _ => None,
        }
    }

    fn update_ema(&mut self, sample: PathSample) {
        let a = self.config.alpha.clamp(0.001, 1.0);
        if let Some(lat) = sample.latency_ms {
            if lat.is_finite() && lat >= 0.0 {
                let prev = self.latency_ms;
                self.latency_ms = if self.samples <= 1 {
                    lat
                } else {
                    a * lat + (1.0 - a) * prev
                };
                self.variance_ms = if self.samples <= 1 {
                    0.0
                } else {
                    let d = (lat - self.latency_ms).abs();
                    a * d + (1.0 - a) * self.variance_ms
                };
            }
        }
        if let Some(loss) = sample.loss_pct {
            if loss.is_finite() && loss >= 0.0 {
                self.loss_pct = if self.samples <= 1 {
                    loss
                } else {
                    a * loss + (1.0 - a) * self.loss_pct
                };
            }
        }
    }

    /// Current evidence as a serializable view with human-readable reasons.
    pub fn view(&self) -> PathHealthView {
        PathHealthView {
            state: self.state.label().to_ascii_lowercase(),
            latency_ms: (self.samples > 0).then_some(self.latency_ms),
            variance_ms: (self.samples > 0).then_some(self.variance_ms),
            loss_pct: (self.samples > 0).then_some(self.loss_pct),
            samples: self.samples,
            failures: self.failures,
            consecutive_failures: self.consecutive_bad,
            reasons: self.reasons(),
        }
    }

    fn reasons(&self) -> Vec<String> {
        let mut r = Vec::new();
        let th = self.config.latency_threshold_ms;
        let loss_th = self.config.loss_threshold_pct;
        match self.state {
            PathState::Unknown => r.push("Collecting path samples…".into()),
            PathState::Healthy => {
                r.push(if self.samples > 0 {
                    format!("Path healthy (RTT {:.0} ms)", self.latency_ms)
                } else {
                    "Path healthy".into()
                });
            }
            PathState::Degraded => {
                if th.is_finite() && self.latency_ms > th {
                    r.push(format!(
                        "RTT {:.0} ms exceeds {:.0} ms threshold",
                        self.latency_ms, th
                    ));
                }
                if loss_th.is_finite() && self.loss_pct > loss_th {
                    r.push(format!(
                        "Packet loss {:.1}% exceeds {:.1}% threshold",
                        self.loss_pct, loss_th
                    ));
                }
                if r.is_empty() {
                    r.push("Path degraded below thresholds".into());
                }
            }
            PathState::Failing => {
                r.push(format!(
                    "{} consecutive probe failures (threshold {})",
                    self.consecutive_bad, self.config.enter_degraded
                ));
                if self.failures > 0 {
                    r.push(format!("{} total connectivity failures", self.failures));
                }
            }
        }
        if !self.config.latency_threshold_ms.is_finite()
            && self.state == PathState::Failing
            && self.consecutive_bad == 0
        {
            // Unreachable only (no latency threshold configured): still make
            // the reason actionable.
            r.push("Connectivity probe failed".into());
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PathHealthConfig {
        PathHealthConfig {
            latency_threshold_ms: 150.0,
            loss_threshold_pct: 5.0,
            enter_degraded: 2,
            exit_degraded: 2,
            cooldown: Duration::from_secs(0),
            alpha: 0.5,
        }
    }

    fn latency(l: f64) -> PathSample {
        PathSample {
            latency_ms: Some(l),
            loss_pct: None,
            reachable: true,
            degraded_evidence: false,
        }
    }

    #[test]
    fn starts_unknown_and_recovers_to_healthy() {
        let mut h = PathHealth::new(cfg());
        assert_eq!(h.state(), PathState::Unknown);
        // A single healthy sample is enough to judge the path healthy.
        let t = h.observe(latency(20.0));
        assert_eq!(t, None);
        assert_eq!(h.state(), PathState::Healthy);
    }

    #[test]
    fn single_latency_blip_does_not_degrade() {
        let mut h = PathHealth::new(cfg());
        h.observe(latency(20.0));
        h.observe(latency(25.0));
        let t = h.observe(latency(900.0)); // one blip
        assert_eq!(t, None);
        assert_eq!(h.state(), PathState::Healthy);
        // Sustained high latency crosses the hysteresis threshold.
        let t = h.observe(latency(800.0));
        assert_eq!(t, Some(PathTransition::EnteredDegraded));
        assert_eq!(h.state(), PathState::Degraded);
    }

    #[test]
    fn connectivity_failures_open_failing() {
        let mut h = PathHealth::new(cfg());
        h.observe(PathSample::healthy());
        assert_eq!(
            h.observe(PathSample::failure()),
            None,
            "one failure is below enter_degraded"
        );
        let t = h.observe(PathSample::failure());
        assert_eq!(t, Some(PathTransition::EnteredFailing));
        assert_eq!(h.state(), PathState::Failing);
    }

    #[test]
    fn recovery_requires_exit_degraded_good_samples() {
        let mut h = PathHealth::new(cfg());
        h.observe(PathSample::healthy());
        h.observe(PathSample::failure());
        h.observe(PathSample::failure());
        assert_eq!(h.state(), PathState::Failing);
        // One good sample is not enough (exit_degraded = 2).
        assert_eq!(h.observe(latency(10.0)), None);
        assert_eq!(h.state(), PathState::Failing);
        let t = h.observe(latency(10.0));
        assert_eq!(t, Some(PathTransition::Recovered));
        assert_eq!(h.state(), PathState::Healthy);
    }

    #[test]
    fn loss_sustained_degrades() {
        let mut h = PathHealth::new(cfg());
        h.observe(PathSample::healthy());
        assert_eq!(h.observe(loss_sample(9.0)), None, "below enter_degraded");
        let t = h.observe(loss_sample(11.0));
        assert_eq!(t, Some(PathTransition::EnteredDegraded));
        let view = h.view();
        assert!(
            view.reasons
                .iter()
                .any(|r| r.contains("Packet loss") && r.contains("threshold")),
            "reasons must explain the degradation: {view:?}"
        );
        // EMA-smoothed loss sits between the two observed values.
        let loss = view.loss_pct.unwrap();
        assert!(loss > 5.0 && loss < 11.0, "EMA loss {loss} in (5, 11)");
    }

    fn loss_sample(pct: f64) -> PathSample {
        PathSample {
            latency_ms: None,
            loss_pct: Some(pct),
            reachable: true,
            degraded_evidence: false,
        }
    }

    #[test]
    fn ema_smooths_and_variance_grows() {
        let mut h = PathHealth::new(cfg());
        h.observe(latency(100.0));
        h.observe(latency(100.0));
        h.observe(latency(200.0));
        // EMA(0.5): 100, 100, 150; variance 0, 0, 25
        let v = h.view();
        assert!(v.latency_ms.unwrap() > 100.0 && v.latency_ms.unwrap() < 200.0);
        assert!(v.variance_ms.unwrap() > 0.0);
    }

    #[test]
    fn cooldown_gates_improvement_but_not_worsening() {
        let mut h = PathHealth::new(PathHealthConfig {
            cooldown: Duration::from_secs(3600),
            ..cfg()
        });
        h.observe(PathSample::healthy());
        h.observe(PathSample::failure());
        h.observe(PathSample::failure());
        assert_eq!(
            h.state(),
            PathState::Failing,
            "worsening must never be gated by cooldown"
        );
        // Improvement is cooldown-gated even after enough good samples.
        h.observe(latency(10.0));
        h.observe(latency(10.0));
        assert_eq!(
            h.state(),
            PathState::Failing,
            "cooldown must hold the state until the interval elapses"
        );
    }

    #[test]
    fn degraded_evidence_counts_without_fake_numbers() {
        let mut h = PathHealth::new(cfg());
        h.observe(PathSample::healthy());
        // Heavy retransmits with a low RTT: qualitative evidence only.
        let sample = PathSample {
            latency_ms: Some(20.0),
            loss_pct: None,
            reachable: true,
            degraded_evidence: true,
        };
        assert_eq!(h.observe(sample), None, "below enter_degraded");
        let t = h.observe(sample);
        assert_eq!(t, Some(PathTransition::EnteredDegraded));
        let view = h.view();
        let lat = view.latency_ms.unwrap();
        assert!(
            lat > 10.0 && lat <= 20.0,
            "EMA latency {lat} converges toward the measured 20 ms"
        );
        assert_eq!(view.state, "degraded");
    }

    #[test]
    fn reset_clears_tracker() {
        let mut h = PathHealth::new(cfg());
        h.observe(PathSample::failure());
        h.observe(PathSample::failure());
        assert_eq!(h.state(), PathState::Failing);
        h.reset();
        assert_eq!(h.state(), PathState::Unknown);
        assert_eq!(h.samples(), 0);
    }

    #[test]
    fn view_state_labels_match_webui() {
        let mut h = PathHealth::new(cfg());
        assert_eq!(h.view().state, "unknown");
        h.observe(PathSample::healthy());
        assert_eq!(h.view().state, "healthy");
        h.observe(PathSample::failure());
        h.observe(PathSample::failure());
        assert_eq!(h.view().state, "failing");
    }
}
