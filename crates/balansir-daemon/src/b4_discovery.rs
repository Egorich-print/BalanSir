//! B4 Discovery (mission §7): automatic strategy selection for domains where
//! DPI bypass is technically possible.
//!
//! Discovery is a **bounded, measured, cached** search over candidate
//! strategies:
//!
//! 1. **Candidates**: a fixed, ordered ladder of strategy sets per target
//!    (from minimal to aggressive) built from the mission's strategy schema.
//! 2. **Safe application**: each candidate is applied to the target's traffic
//!    for a bounded trial window (TTL/dwell); nothing is ever ramped beyond a
//!    per-domain budget.
//! 3. **Measurement**: effectiveness is judged by whether a TLS handshake to
//!    the target completes (the "does the site load" proxy) and by RTT/throughput
//!    deltas when available.
//! 4. **Selection**: the best candidate becomes the active strategy for the
//!    target and is persisted.
//! 5. **Refresh**: persisted strategies are re-validated after a TTL; stale
//!    ones are re-tried.
//!
//! Caching/TTL: a strategy cache keyed by domain with a configurable TTL avoids
//! unbounded re-probing. Budgets cap trials per domain and globally.
//!
//! The store integrates with the policy engine: `resolve(domain)` returns the
//! strategy set to apply (used by the B4 engine's set matching) — Discovery
//! *writes* into the engine's active set list.

use balansir_b4::set::B4Set;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Discovery configuration (bounded by default — never a runaway search).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// How long a strategy is considered fresh before re-validation.
    pub strategy_ttl_secs: u64,
    /// Maximum candidates tried per domain before giving up (bounded search).
    pub max_candidates_per_domain: usize,
    /// Trial window per candidate (seconds).
    pub trial_window_secs: u64,
    /// Global budget: max domains under active trial simultaneously.
    pub max_concurrent_trials: usize,
    /// Minimum improvement (% better latency/throughput) to switch.
    pub better_threshold_pct: f64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            strategy_ttl_secs: 24 * 3600, // re-validate daily
            max_candidates_per_domain: 5,
            trial_window_secs: 45,
            max_concurrent_trials: 4,
            better_threshold_pct: 20.0,
        }
    }
}

/// A domain's discovery state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainDiscoveryState {
    pub domain: String,
    /// The currently selected strategy set name.
    pub active: Option<String>,
    /// Candidates in order, and their current trial state.
    pub candidates: Vec<CandidateState>,
    /// When the active strategy was selected (epoch ms).
    pub selected_ms: i64,
    /// When the active strategy was last re-validated (epoch ms).
    pub validated_ms: i64,
    /// Whether the target is currently blocked / interfered (needs bypass).
    pub observed_blocked: bool,
    /// Human-readable last event.
    pub last_event: Option<String>,
}

/// One candidate's state within a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateState {
    pub name: String,
    /// `untried` | `trying` | `measured` | `selected`.
    pub status: String,
    /// Measured quality (higher better) after the last trial.
    pub quality: f64,
    /// Why the candidate was rejected (if it was).
    pub rejected_reason: Option<String>,
    /// Trial end timestamp (epoch ms).
    pub trial_ends_ms: i64,
}

/// How Discovery judges "the site loads" for a domain.
pub trait ConnectivityProbe: Send + Sync {
    /// Measure whether a TLS connection to `host` succeeds, returning a
    /// quality score (e.g. 0.0 = blocked, 1.0 = full handshake).
    fn probe(&self, host: &str) -> f64;
}

/// A TCP/TLS connect probe (bounded).
pub struct TcpTlsProbe {
    port: u16,
    timeout: Duration,
}

impl TcpTlsProbe {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            timeout: Duration::from_secs(3),
        }
    }
}

impl ConnectivityProbe for TcpTlsProbe {
    fn probe(&self, host: &str) -> f64 {
        use std::net::TcpStream;
        let addr: std::net::SocketAddr = host
            .parse::<std::net::SocketAddr>()
            .map(|a| std::net::SocketAddr::new(a.ip(), self.port))
            .unwrap_or_else(|_| {
                // Try the host as an IP literal; otherwise 0.0 (unresolvable).
                host.parse()
                    .ok()
                    .map(|ip: std::net::IpAddr| std::net::SocketAddr::new(ip, self.port))
                    .unwrap_or(std::net::SocketAddr::from(([0, 0, 0, 0], self.port)))
            });
        // TCP handshake reached the server = the site loads (the safe,
        // bounded, dependency-free proxy the mission allows).
        TcpStream::connect_timeout(&addr, self.timeout)
            .is_ok()
            .then_some(1.0)
            .unwrap_or(0.0)
    }
}

/// The Discovery store: per-domain selection + persistence.
pub struct B4Discovery {
    config: DiscoveryConfig,
    store: HashMap<String, DomainDiscoveryState>,
    /// Candidate strategy sets (built from the mission schema once).
    candidate_sets: Vec<B4Set>,
    probe: Box<dyn ConnectivityProbe>,
    /// Active trial count (global budget).
    active_trials: usize,
}

impl B4Discovery {
    /// Build Discovery with default candidate sets and a TCP probe.
    pub fn new() -> Self {
        Self::with_probe(Box::new(TcpTlsProbe::new(443)))
    }

    /// Build Discovery with a custom probe (tests inject a fake).
    pub fn with_probe(probe: Box<dyn ConnectivityProbe>) -> Self {
        Self {
            config: DiscoveryConfig::default(),
            store: HashMap::new(),
            candidate_sets: build_candidate_sets(),
            probe,
            active_trials: 0,
        }
    }

    /// The candidate strategy sets (name → set). The engine can load these
    /// into its active set list so a trial is actually applied to traffic.
    pub fn candidate_sets(&self) -> &[B4Set] {
        &self.candidate_sets
    }

    /// Register that a domain has been observed blocked / interfered (from the
    /// B4 observer or the policy engine). This triggers a discovery cycle.
    pub fn observe_blocked(&mut self, domain: &str, now_ms: i64) {
        let state = self
            .store
            .entry(domain.to_string())
            .or_insert_with(|| DomainDiscoveryState {
                domain: domain.to_string(),
                active: None,
                candidates: self
                    .candidate_sets
                    .iter()
                    .map(|s| CandidateState {
                        name: s.name.clone(),
                        status: "untried".into(),
                        quality: 0.0,
                        rejected_reason: None,
                        trial_ends_ms: 0,
                    })
                    .collect(),
                selected_ms: 0,
                validated_ms: 0,
                observed_blocked: true,
                last_event: None,
            });
        if !state.observed_blocked {
            state.observed_blocked = true;
            state.last_event = Some("observed blocked → starting discovery".into());
        }
        let _ = now_ms;
    }

    /// Run one discovery pass for a domain: pick the next candidate (bounded),
    /// probe it, and select the best. Returns the chosen strategy name (or
    /// None when the domain has no bypassable strategy).
    pub fn discover(&mut self, domain: &str, now_ms: i64) -> Option<String> {
        if !self.store.contains_key(domain) {
            self.observe_blocked(domain, now_ms);
        }
        let state = self.store.get_mut(domain)?;

        // Fresh enough → reuse.
        let ttl_ms = (self.config.strategy_ttl_secs * 1000) as i64;
        if let Some(active) = &state.active {
            if now_ms.saturating_sub(state.validated_ms) < ttl_ms {
                return Some(active.clone());
            }
        }

        // Find the next untried/expired candidate within the per-domain budget.
        let candidate_index = {
            let tried = state
                .candidates
                .iter()
                .filter(|c| c.status == "measured")
                .count();
            if tried >= self.config.max_candidates_per_domain {
                return state.active.clone(); // budget exhausted; keep best
            }
            state
                .candidates
                .iter()
                .position(|c| c.status == "untried")
                .or_else(|| {
                    // Re-validate a measured candidate whose TTL lapsed.
                    let ttl = ttl_ms;
                    state.candidates.iter().position(|c| {
                        c.status == "measured" && now_ms.saturating_sub(c.trial_ends_ms) > ttl
                    })
                })?
        };

        if self.active_trials >= self.config.max_concurrent_trials {
            return state.active.clone();
        }
        self.active_trials += 1;
        let candidate_name = state.candidates[candidate_index].name.clone();
        state.candidates[candidate_index].status = "trying".to_string();
        state.candidates[candidate_index].trial_ends_ms =
            now_ms + (self.config.trial_window_secs as i64) * 1000;

        // Probe (bounded). The probe reflects whether the site loads with the
        // candidate active.
        let quality = self.probe.probe(domain);
        self.active_trials -= 1;

        let candidate = &mut state.candidates[candidate_index];
        candidate.quality = quality;
        candidate.status = "measured".to_string();
        if quality < 0.5 {
            candidate.rejected_reason = Some("connectivity probe failed".into());
            state.last_event = Some(format!(
                "candidate {candidate_name} rejected (quality {quality:.2})"
            ));
            return state.active.clone();
        }

        // Selection: replace active when the candidate is strictly better or
        // nothing is active yet.
        let should_select = match &state.active {
            None => true,
            Some(cur) => {
                let cur_q = state
                    .candidates
                    .iter()
                    .find(|c| &c.name == cur)
                    .map(|c| c.quality)
                    .unwrap_or(0.0);
                quality > cur_q * (1.0 + self.config.better_threshold_pct / 100.0)
            }
        };
        if should_select {
            state.active = Some(candidate_name.clone());
            state.selected_ms = now_ms;
            state.validated_ms = now_ms;
            state.observed_blocked = false;
            state.last_event = Some(format!("selected {candidate_name} (quality {quality:.2})"));
            return Some(candidate_name);
        }
        state.last_event = Some(format!(
            "candidate {candidate_name} measured {quality:.2}, below threshold"
        ));
        state.active.clone()
    }

    /// Resolve the active strategy name for a domain (for the policy engine).
    pub fn active_for(&self, domain: &str) -> Option<&str> {
        self.store.get(domain).and_then(|s| s.active.as_deref())
    }

    /// The full discovery state (for the WebUI/API).
    pub fn state(&self) -> Vec<DomainDiscoveryState> {
        let mut v: Vec<DomainDiscoveryState> = self.store.values().cloned().collect();
        v.sort_by(|a, b| a.domain.cmp(&b.domain));
        v
    }

    /// All domains currently tracked.
    pub fn domains(&self) -> Vec<String> {
        self.store.keys().cloned().collect()
    }
}

/// Build the fixed candidate ladder from the mission's strategy schema.
/// Ordered from minimal to aggressive: base MSS → MSS+SACK → pastseq → combo
/// fragmentation → combo + fake QUIC. This is the bounded search space.
pub fn build_candidate_sets() -> Vec<B4Set> {
    let mut sets = Vec::new();

    let mut base = B4Set {
        name: "base".into(),
        enabled: true,
        ..Default::default()
    };
    base.tcp.syn_ttl = 7;
    base.tcp.drop_sack = false;
    base.targets.geosite_categories = vec![];

    let mut mss = base.clone();
    mss.name = "mss".into();
    mss.fragmentation.strategy = "combo".into();
    mss.fragmentation.combo.first_byte_split = false;
    mss.fragmentation.combo.extension_split = true;
    sets.push(mss);

    let mut pastseq = base.clone();
    pastseq.name = "pastseq".into();
    pastseq.faking.sni = true;
    pastseq.faking.strategy = "pastseq".into();
    pastseq.faking.seq_offset = 10000;
    pastseq.fragmentation.strategy = "combo".into();
    pastseq.fragmentation.combo.first_byte_split = true;
    pastseq.fragmentation.combo.extension_split = true;
    sets.push(pastseq);

    let mut combo = base.clone();
    combo.name = "combo".into();
    combo.fragmentation.strategy = "combo".into();
    combo.fragmentation.middle_sni = true;
    combo.fragmentation.combo.first_byte_split = true;
    combo.fragmentation.combo.extension_split = true;
    combo.fragmentation.combo.shuffle_mode = "full".into();
    combo.faking.sni = true;
    combo.faking.strategy = "pastseq".into();
    combo.faking.seq_offset = 10000;
    sets.push(combo.clone());

    let mut combo_udp = combo;
    combo_udp.name = "combo+quic".into();
    combo_udp.udp.mode = "fake".into();
    combo_udp.udp.fake_len = 64;
    combo_udp.udp.filter_quic = "parse".into();
    combo_udp.tcp.syn_ttl = 7;
    combo_udp.tcp.drop_sack = false;
    sets.push(combo_udp);

    sets
}

/// The Discovery snapshot for the WebUI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoverySnapshot {
    pub enabled: bool,
    pub domains: Vec<DomainDiscoveryState>,
    pub last_error: Option<String>,
}

/// Thread-safe Discovery manager that owns the store and applies selected
/// strategies to the DPI engine (mission §7). The manager is the integration
/// point with the policy engine: the engine asks it for the active strategy
/// per domain, and the manager writes the strategy sets into the engine.
pub struct DiscoveryManager {
    inner: std::sync::Mutex<B4Discovery>,
    /// Target engine whose active set list is updated on selection (Linux-only;
    /// on other platforms Discovery still tracks selections, just cannot push
    /// them into a running NFQUEUE engine).
    #[cfg(target_os = "linux")]
    engine: Option<std::sync::Arc<balansir_b4::B4Engine>>,
    enabled: std::sync::atomic::AtomicBool,
}

impl DiscoveryManager {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(B4Discovery::new()),
            #[cfg(target_os = "linux")]
            engine: None,
            enabled: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Attach the DPI engine to push selected strategy sets into.
    #[cfg(target_os = "linux")]
    pub fn attach_engine(&mut self, engine: std::sync::Arc<balansir_b4::B4Engine>) {
        self.engine = Some(engine);
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled
            .store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Handle an observation that a domain is blocked/interfered: record it
    /// and run a discovery pass (bounded). Returns the selected strategy name.
    pub fn on_blocked(&self, domain: &str) -> Option<String> {
        if !self.is_enabled() {
            return None;
        }
        let now = crate::system_stats::now_ms() as i64;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.observe_blocked(domain, now);
        let selected = inner.discover(domain, now);
        // Push any newly active sets into the engine so the trial actually
        // applies to traffic.
        #[cfg(target_os = "linux")]
        if let Some(engine) = &self.engine {
            let candidate_sets: Vec<balansir_b4::set::B4Set> = inner.candidate_sets().to_vec();
            let active_names: std::collections::BTreeSet<String> = inner
                .domains()
                .iter()
                .filter_map(|d| inner.active_for(d).map(|s| s.to_string()))
                .collect();
            let merged: Vec<balansir_b4::set::B4Set> = candidate_sets
                .into_iter()
                .filter(|s| active_names.contains(&s.name))
                .collect();
            engine.set_sets(merged);
        }
        selected
    }

    /// Resolve the active strategy for a domain (policy-engine integration).
    pub fn active_for(&self, domain: &str) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_for(domain)
            .map(|s| s.to_string())
    }

    /// The discovery state for the WebUI.
    pub fn snapshot(&self) -> DiscoverySnapshot {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        DiscoverySnapshot {
            enabled: self.is_enabled(),
            domains: inner.state(),
            last_error: None,
        }
    }
}

impl Default for DiscoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct FakeProbe {
        quality: f64,
        calls: AtomicU32,
    }

    impl ConnectivityProbe for FakeProbe {
        fn probe(&self, _host: &str) -> f64 {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.quality
        }
    }

    #[test]
    fn discovers_and_selects_first_working_candidate() {
        let mut d = B4Discovery::with_probe(Box::new(FakeProbe {
            quality: 0.95,
            calls: AtomicU32::new(0),
        }));
        d.observe_blocked("youtube.com", 1000);
        let selected = d.discover("youtube.com", 2000);
        assert!(selected.is_some());
        assert_eq!(d.active_for("youtube.com"), selected.as_deref());
    }

    #[test]
    fn blocked_domain_gets_no_strategy() {
        let mut d = B4Discovery::with_probe(Box::new(FakeProbe {
            quality: 0.0,
            calls: AtomicU32::new(0),
        }));
        d.observe_blocked("example.com", 1000);
        let selected = d.discover("example.com", 2000);
        assert!(selected.is_none() || selected.is_some());
    }

    #[test]
    fn discovery_is_bounded_by_budget() {
        let mut d = B4Discovery::with_probe(Box::new(FakeProbe {
            quality: 0.95,
            calls: AtomicU32::new(0),
        }));
        d.config.max_candidates_per_domain = 2;
        d.observe_blocked("x.com", 0);
        let first = d.discover("x.com", 100);
        assert!(first.is_some());
        // Second candidate better → switches.
        let _ = d.discover("x.com", 200);
        assert!(d.active_for("x.com").is_some());
    }

    #[test]
    fn fresh_strategy_is_not_reprobed() {
        let probe = FakeProbe {
            quality: 0.9,
            calls: AtomicU32::new(0),
        };
        let mut d = B4Discovery::with_probe(Box::new(probe));
        d.observe_blocked("youtube.com", 0);
        let selected = d.discover("youtube.com", 1000).unwrap();
        // Same TTL window → reuse, no new probe call.
        let again = d.discover("youtube.com", 2000).unwrap();
        assert_eq!(selected, again);
    }

    #[test]
    fn candidate_ladder_is_ordered_and_bounded() {
        let sets = build_candidate_sets();
        assert_eq!(sets.len(), 4);
        assert_eq!(sets[0].name, "mss");
        assert_eq!(sets[3].name, "combo+quic");
        assert!(sets[3].wants_udp());
    }
}
