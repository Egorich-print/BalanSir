//! Unified path pool abstraction (mission §0.6).
//!
//! A `PathPool` represents a set of candidate paths (DIRECT, B4, VPN, etc.)
//! for reaching a destination. The pool evaluates candidates, selects the best
//! one based on health/scoring/strategy, and handles fallback chains.
//!
//! Design:
//! - Policy chooses a **path** (capability), not a concrete driver.
//! - Each candidate has health, score, cooldown, and compatibility metadata.
//! - The pool is pure: no I/O, no network calls. Observations come in;
//!   selections go out.
//! - Integration: the daemon feeds observations from B4/VPN/DNS health;
//!   the pool selects; the daemon applies.

use serde::{Deserialize, Serialize};

/// A path capability the policy can select.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathCapability {
    /// Direct internet path (no adaptation).
    Direct,
    /// B4 packet processing adaptation.
    B4,
    /// WireGuard VPN tunnel.
    WireGuard,
    /// AmneziaWG VPN tunnel.
    AmneziaWG,
    /// Xray VLESS proxy.
    Xray,
    /// Hysteria VPN tunnel.
    Hysteria,
    /// DNS-level blocking (NXDOMAIN).
    Block,
}

impl PathCapability {
    pub fn label(&self) -> &'static str {
        match self {
            PathCapability::Direct => "Direct",
            PathCapability::B4 => "B4",
            PathCapability::WireGuard => "WireGuard",
            PathCapability::AmneziaWG => "AmneziaWG",
            PathCapability::Xray => "Xray",
            PathCapability::Hysteria => "Hysteria",
            PathCapability::Block => "Block",
        }
    }
}

/// Selection strategy for choosing among healthy candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionStrategy {
    /// Highest score wins.
    #[default]
    BestScore,
    /// Strict priority order (lower index = preferred).
    Priority,
    /// Weighted random selection proportional to score.
    Weighted,
    /// Round-robin among healthy candidates.
    RoundRobin,
}

/// Health state of a single path candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateState {
    /// Not yet observed.
    Unknown,
    /// Healthy and available.
    Healthy,
    /// Observed degradation (latency, loss, partial failure).
    Degraded,
    /// Fully failing (not usable).
    Failing,
    /// In cooldown after failure.
    CoolingDown,
}

/// A single path candidate with health/scoring metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCandidate {
    /// The capability this candidate provides.
    pub capability: PathCapability,
    /// Current health state.
    pub state: CandidateState,
    /// Composite score (0.0–1.0). Higher = better.
    pub score: f64,
    /// Success ratio (recent observations).
    pub success_ratio: f64,
    /// Last latency observation (ms), if available.
    pub latency_ms: Option<f64>,
    /// Recent failure count (within observation window).
    pub recent_failures: u32,
    /// Cooldown remaining (seconds). 0 = not in cooldown.
    pub cooldown_remaining: u64,
    /// Whether this candidate is compatible with the current policy.
    pub compatible: bool,
    /// Priority rank (lower = preferred). Used by Priority strategy.
    pub priority: u32,
}

impl PathCandidate {
    /// Whether this candidate is selectable (healthy + compatible + not cooling down).
    pub fn is_selectable(&self) -> bool {
        self.compatible
            && !matches!(self.state, CandidateState::Failing | CandidateState::CoolingDown)
    }

    /// Weighted selection factor (score * compatibility * availability).
    pub fn weight(&self) -> f64 {
        if !self.is_selectable() {
            return 0.0;
        }
        self.score
    }
}

/// A pool of path candidates with selection logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathPool {
    /// Pool name (e.g., "main", "dns", "b4").
    pub name: String,
    /// Ordered candidates.
    pub candidates: Vec<PathCandidate>,
    /// Selection strategy.
    pub strategy: SelectionStrategy,
    /// Last selected index (for round-robin).
    #[serde(skip)]
    last_selected: usize,
}

impl PathPool {
    /// Create a new pool with the given strategy.
    pub fn new(name: String, strategy: SelectionStrategy) -> Self {
        Self {
            name,
            candidates: Vec::new(),
            strategy,
            last_selected: 0,
        }
    }

    /// Add a candidate to the pool.
    pub fn add_candidate(&mut self, candidate: PathCandidate) {
        self.candidates.push(candidate);
    }

    /// Select the best candidate according to the strategy.
    /// Returns None if no selectable candidate exists.
    pub fn select(&mut self) -> Option<&PathCandidate> {
        match self.strategy {
            SelectionStrategy::BestScore => self.select_best_score(),
            SelectionStrategy::Priority => self.select_priority(),
            SelectionStrategy::Weighted => self.select_weighted(),
            SelectionStrategy::RoundRobin => self.select_round_robin(),
        }
    }

    fn select_best_score(&self) -> Option<&PathCandidate> {
        self.candidates
            .iter()
            .filter(|c| c.is_selectable())
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal))
    }

    fn select_priority(&self) -> Option<&PathCandidate> {
        self.candidates
            .iter()
            .filter(|c| c.is_selectable())
            .min_by_key(|c| c.priority)
    }

    fn select_weighted(&self) -> Option<&PathCandidate> {
        let total: f64 = self.candidates.iter().map(|c| c.weight()).sum();
        if total <= 0.0 {
            return None;
        }
        // Deterministic: pick the candidate with highest weight (simplified for RPi).
        self.candidates
            .iter()
            .filter(|c| c.is_selectable())
            .max_by(|a, b| a.weight().partial_cmp(&b.weight()).unwrap_or(std::cmp::Ordering::Equal))
    }

    fn select_round_robin(&mut self) -> Option<&PathCandidate> {
        let n = self.candidates.len();
        if n == 0 {
            return None;
        }
        for _ in 0..n {
            self.last_selected = (self.last_selected + 1) % n;
            if self.candidates[self.last_selected].is_selectable() {
                return Some(&self.candidates[self.last_selected]);
            }
        }
        None
    }

    /// Get the number of selectable candidates.
    pub fn healthy_count(&self) -> usize {
        self.candidates.iter().filter(|c| c.is_selectable()).count()
    }

    /// Get the number of total candidates.
    pub fn total_count(&self) -> usize {
        self.candidates.len()
    }

    /// Find a candidate by capability.
    pub fn find_by_capability(&self, cap: PathCapability) -> Option<&PathCandidate> {
        self.candidates.iter().find(|c| c.capability == cap)
    }

    /// Find a mutable candidate by capability.
    pub fn find_mut_by_capability(&mut self, cap: PathCapability) -> Option<&mut PathCandidate> {
        self.candidates.iter_mut().find(|c| c.capability == cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(cap: PathCapability, score: f64, state: CandidateState) -> PathCandidate {
        PathCandidate {
            capability: cap,
            state,
            score,
            success_ratio: score,
            latency_ms: None,
            recent_failures: 0,
            cooldown_remaining: 0,
            compatible: true,
            priority: 0,
        }
    }

    #[test]
    fn selects_best_score() {
        let mut pool = PathPool::new("test".into(), SelectionStrategy::BestScore);
        pool.add_candidate(candidate(PathCapability::Direct, 0.3, CandidateState::Healthy));
        pool.add_candidate(candidate(PathCapability::B4, 0.8, CandidateState::Healthy));
        pool.add_candidate(candidate(PathCapability::Xray, 0.5, CandidateState::Healthy));
        let sel = pool.select().unwrap();
        assert_eq!(sel.capability, PathCapability::B4);
    }

    #[test]
    fn skips_failing_candidates() {
        let mut pool = PathPool::new("test".into(), SelectionStrategy::BestScore);
        pool.add_candidate(candidate(PathCapability::Direct, 0.3, CandidateState::Healthy));
        pool.add_candidate(candidate(PathCapability::B4, 0.9, CandidateState::Failing));
        let sel = pool.select().unwrap();
        assert_eq!(sel.capability, PathCapability::Direct);
    }

    #[test]
    fn skips_incompatible_candidates() {
        let mut pool = PathPool::new("test".into(), SelectionStrategy::BestScore);
        pool.add_candidate(PathCandidate {
            compatible: false,
            ..candidate(PathCapability::Xray, 0.9, CandidateState::Healthy)
        });
        pool.add_candidate(candidate(PathCapability::Direct, 0.5, CandidateState::Healthy));
        let sel = pool.select().unwrap();
        assert_eq!(sel.capability, PathCapability::Direct);
    }

    #[test]
    fn no_selectable_returns_none() {
        let mut pool = PathPool::new("test".into(), SelectionStrategy::BestScore);
        pool.add_candidate(candidate(PathCapability::B4, 0.5, CandidateState::Failing));
        assert!(pool.select().is_none());
    }

    #[test]
    fn priority_selects_lowest_priority_number() {
        let mut pool = PathPool::new("test".into(), SelectionStrategy::Priority);
        pool.add_candidate(PathCandidate {
            priority: 5,
            ..candidate(PathCapability::Xray, 0.5, CandidateState::Healthy)
        });
        pool.add_candidate(PathCandidate {
            priority: 1,
            ..candidate(PathCapability::Direct, 0.3, CandidateState::Healthy)
        });
        let sel = pool.select().unwrap();
        assert_eq!(sel.capability, PathCapability::Direct);
    }

    #[test]
    fn round_robin_cycles() {
        let mut pool = PathPool::new("test".into(), SelectionStrategy::RoundRobin);
        pool.add_candidate(candidate(PathCapability::Direct, 0.5, CandidateState::Healthy));
        pool.add_candidate(candidate(PathCapability::B4, 0.5, CandidateState::Healthy));
        let s1 = pool.select().unwrap().capability;
        let s2 = pool.select().unwrap().capability;
        assert_ne!(s1, s2);
    }

    #[test]
    fn find_by_capability() {
        let mut pool = PathPool::new("test".into(), SelectionStrategy::BestScore);
        pool.add_candidate(candidate(PathCapability::Direct, 0.5, CandidateState::Healthy));
        pool.add_candidate(candidate(PathCapability::B4, 0.8, CandidateState::Healthy));
        assert!(pool.find_by_capability(PathCapability::B4).is_some());
        assert!(pool.find_by_capability(PathCapability::Xray).is_none());
    }

    #[test]
    fn healthy_count_excludes_failing() {
        let mut pool = PathPool::new("test".into(), SelectionStrategy::BestScore);
        pool.add_candidate(candidate(PathCapability::Direct, 0.5, CandidateState::Healthy));
        pool.add_candidate(candidate(PathCapability::B4, 0.8, CandidateState::Failing));
        pool.add_candidate(candidate(PathCapability::Xray, 0.6, CandidateState::Degraded));
        assert_eq!(pool.healthy_count(), 2); // Direct + Xray (Degraded is still selectable)
    }
}
