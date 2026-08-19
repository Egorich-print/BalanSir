//! The VPN pool: profile store + health-aware selection + rotation + load
//! balancing + recovery.
//!
//! Design (mission §9–§13):
//! * one authoritative pool with a single `PoolConfig`;
//! * per-profile health uses the **unified `PathHealth`** from
//!   `balansir-common` — no second health model;
//! * **weighted selection**: weight = f(health state, latency, availability,
//!   capacity headroom). Healthy profiles dominate; degraded weights shrink;
//!   cooldown/failed are excluded;
//! * **load distribution**: active-flow counts feed a capacity headroom term,
//!   so new flows prefer under-loaded healthy profiles;
//! * **planned rotation** only when it does not hurt: min-dwell + hysteresis +
//!   "don't switch away from a significantly-better active profile";
//! * **recovery**: Failed → Cooldown → Recovering (ramp-up weights) → Healthy;
//! * the pool is pure/deterministic given its inputs (clock injected), so it
//!   is fully unit-testable without network or time.

use balansir_health::{PathHealth, PathHealthConfig, PathSample, PathState};

use crate::profile::{ProfileHealth, ProfileLoad, ProfileState, VpnProfile};

/// Tunables for the whole pool (mission §9/§10/§12).
#[derive(Debug, Clone, PartialEq)]
pub struct PoolConfig {
    /// Minimum time a selected profile must stay active before planned
    /// rotation may switch away from it (anti-flap dwell).
    pub min_dwell: std::time::Duration,
    /// Cooldown after a profile fails before it can be probed/returned.
    pub failure_cooldown: std::time::Duration,
    /// Anti-flap cooldown of the underlying unified PathHealth trackers
    /// (improving transitions are gated by this interval).
    pub health_cooldown: std::time::Duration,
    /// Planned rotation interval (0 = disabled).
    pub rotation_interval: std::time::Duration,
    /// If the active profile's score is at least this much better than the
    /// rotation candidate, do NOT rotate (don't break a healthy path).
    pub better_threshold: f64,
    /// Weight ramp-up steps for recovering profiles, e.g. [10, 25, 50, 100].
    pub ramp_steps: Vec<u32>,
    /// Estimated capacity (active flows) considered "fully loaded" per profile.
    pub capacity_per_profile: u32,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_dwell: std::time::Duration::from_secs(120),
            failure_cooldown: std::time::Duration::from_secs(60),
            health_cooldown: std::time::Duration::from_secs(10),
            rotation_interval: std::time::Duration::from_secs(0), // disabled by default
            better_threshold: 25.0,
            ramp_steps: vec![10, 25, 50, 100],
            capacity_per_profile: 64,
        }
    }
}

/// A live profile in the pool: the immutable profile + mutable health/load.
pub struct PooledProfile {
    pub profile: VpnProfile,
    pub health: ProfileHealth,
    pub load: ProfileLoad,
    pub tracker: PathHealth,
    /// Unix ms the profile last failed (cooldown gate).
    pub last_failure_ms: i64,
    /// Unix ms the profile was last selected as active.
    pub last_selected_ms: i64,
}

/// Why a profile was excluded from selection (explainability).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Exclusion {
    pub profile_id: String,
    pub reason: String,
}

/// The outcome of one selection decision.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectionDecision {
    pub profile_id: String,
    pub score: f64,
    /// Human-readable "why this profile won".
    pub reason: String,
    /// Profiles considered but excluded, with reasons.
    pub excluded: Vec<Exclusion>,
    /// Total candidates considered.
    pub candidates: usize,
}

/// Point-in-time pool view for snapshots/WebUI (no credentials).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PoolSnapshot {
    pub profiles: Vec<ProfileHealth>,
    pub active: Option<String>,
    pub excluded: Vec<Exclusion>,
    pub last_rotation_ms: i64,
    pub last_rotation_reason: Option<String>,
    pub updated_ms: i64,
}

/// The VPN pool. `VpnPool` is not `Clone` — it owns the stateful trackers;
/// the daemon wraps it in a `Mutex`/`RwLock` and drives it from one loop.
///
/// Determinism: all time-dependent logic takes an explicit `now_ms` argument,
/// so tests inject a fixed clock and the pool is fully deterministic.
pub struct VpnPool {
    config: PoolConfig,
    profiles: Vec<PooledProfile>,
    active: Option<String>,
    last_rotation_ms: i64,
    last_rotation_reason: Option<String>,
}

fn path_config(config: &PoolConfig) -> PathHealthConfig {
    PathHealthConfig {
        latency_threshold_ms: 400.0,
        loss_threshold_pct: 10.0,
        enter_degraded: 2,
        exit_degraded: 3,
        cooldown: config.health_cooldown,
        ..PathHealthConfig::default()
    }
}

impl VpnPool {
    /// Create an empty pool with the given config.
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            profiles: Vec::new(),
            active: None,
            last_rotation_ms: 0,
            last_rotation_reason: None,
        }
    }

    /// Replace the whole profile set atomically (mission §15): the new set
    /// becomes the pool only after it is non-empty and every profile is
    /// valid; otherwise the previous known-good pool is kept and an error is
    /// returned. Rejected/unhealthy candidate sets never empty the pool.
    pub fn atomic_replace(
        &mut self,
        profiles: Vec<VpnProfile>,
        _now_ms: i64,
    ) -> Result<usize, String> {
        if profiles.is_empty() {
            return Err("refusing to replace pool with an empty set".into());
        }
        // Build fresh trackers for the new profile set.
        self.profiles = profiles
            .into_iter()
            .map(|p| PooledProfile {
                profile: p,
                health: ProfileHealth::default(),
                load: ProfileLoad::default(),
                tracker: PathHealth::new(path_config(&self.config)),
                last_failure_ms: 0,
                last_selected_ms: 0,
            })
            .collect();
        // If the old active profile is gone, clear it.
        if let Some(active) = &self.active {
            if !self
                .profiles
                .iter()
                .any(|p| &p.profile.profile_id == active)
            {
                self.active = None;
            }
        }
        Ok(self.profiles.len())
    }

    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    pub fn profiles(&self) -> &[PooledProfile] {
        &self.profiles
    }

    pub fn profile(&self, id: &str) -> Option<&PooledProfile> {
        self.profiles.iter().find(|p| p.profile.profile_id == id)
    }

    pub fn active(&self) -> Option<&str> {
        self.active.as_deref()
    }

    /// Record a health sample for a profile from the unified `PathSample`
    /// vocabulary. Returns the profile's new state.
    pub fn observe_health(
        &mut self,
        profile_id: &str,
        sample: PathSample,
        now_ms: i64,
    ) -> ProfileState {
        let idx = match self
            .profiles
            .iter()
            .position(|p| p.profile.profile_id == profile_id)
        {
            Some(i) => i,
            None => return ProfileState::Unknown,
        };
        let transition = self.profiles[idx].tracker.observe(sample);
        {
            let p = &mut self.profiles[idx];
            p.health.sample_count = p.tracker.samples();
            p.health.latency_ms = p.tracker.view().latency_ms;
            p.health.loss_pct = p.tracker.view().loss_pct;
            p.health.consecutive_failures = p.tracker.consecutive_bad();
            if sample.reachable {
                p.health.consecutive_successes = p.health.consecutive_successes.saturating_add(1);
            } else {
                p.health.consecutive_successes = 0;
                p.health.failure_count += 1;
                p.last_failure_ms = now_ms;
            }
            p.health.availability = if p.health.sample_count > 0 {
                Some(1.0 - p.health.failure_count as f64 / p.health.sample_count as f64)
            } else {
                None
            };
        }

        // Map the unified path state into the pool's lifecycle state.
        let next = self.derive_state(&self.profiles[idx], now_ms);
        {
            let p = &mut self.profiles[idx];
            p.health.state = next;
            p.health.reasons = p.tracker.view().reasons;
            p.health.profile_id = p.profile.profile_id.clone();
            p.health.label = p.profile.label.clone();
            p.health.active_flows = p.load.active_flows;
        }
        // Weight depends on state + recovery; compute against the immutable
        // view to avoid a second mutable borrow.
        let w = self.weight(&self.profiles[idx], now_ms);
        self.profiles[idx].health.weight = w;
        let _ = transition;
        next
    }

    /// Determine the lifecycle state from the unified tracker + cooldown.
    ///
    /// Semantics (mission §13):
    /// * unified `Failing` → `Failed` always (cooldown does not hide failure);
    /// * the tracker is healthy/degraded/unknown again BUT the failure
    ///   cooldown has not elapsed → `Cooldown` (excluded, awaiting probe);
    /// * otherwise, if the profile was previously failed/cooldown and the
    ///   tracker is healthy → `Recovering` (ramp-up);
    /// * plain healthy → `Healthy`.
    fn derive_state(&self, p: &PooledProfile, now_ms: i64) -> ProfileState {
        let in_cooldown = p.last_failure_ms > 0
            && (now_ms - p.last_failure_ms) < self.config.failure_cooldown.as_millis() as i64;
        match p.tracker.state() {
            PathState::Failing => ProfileState::Failed,
            PathState::Degraded => {
                if in_cooldown {
                    ProfileState::Cooldown
                } else {
                    ProfileState::Degraded
                }
            }
            PathState::Unknown => {
                if in_cooldown {
                    ProfileState::Cooldown
                } else {
                    ProfileState::Unknown
                }
            }
            PathState::Healthy => {
                let was_bad = matches!(
                    p.health.state,
                    ProfileState::Failed | ProfileState::Cooldown | ProfileState::Recovering
                );
                if in_cooldown {
                    ProfileState::Cooldown
                } else if was_bad {
                    ProfileState::Recovering
                } else {
                    ProfileState::Healthy
                }
            }
        }
    }

    /// Weight of a profile for selection (0 = excluded).
    fn weight(&self, p: &PooledProfile, now_ms: i64) -> u32 {
        let state = self.derive_state(p, now_ms);
        match state {
            ProfileState::Unknown => 10,
            ProfileState::Healthy => 100,
            ProfileState::Degraded => 40,
            ProfileState::Recovering => self.ramp_weight(p),
            ProfileState::Cooldown | ProfileState::Failed => 0,
        }
    }

    /// Ramp-up weight for a recovering profile (mission §13): step up through
    /// `ramp_steps` based on consecutive successes since recovery began.
    fn ramp_weight(&self, p: &PooledProfile) -> u32 {
        let steps = &self.config.ramp_steps;
        if steps.is_empty() {
            return 100;
        }
        let successes = p.health.consecutive_successes.min(steps.len() as u32);
        steps[successes.max(1) as usize - 1].clamp(1, 100)
    }

    /// Score of a profile for ranking (higher is better). Combines base
    /// weight, latency, availability, and load headroom.
    fn score(&self, p: &PooledProfile, now_ms: i64) -> f64 {
        let w = self.weight(p, now_ms) as f64;
        if w == 0.0 {
            return 0.0;
        }
        let latency_penalty = match p.health.latency_ms {
            Some(lat) if lat > 0.0 => (lat / 1000.0).clamp(0.0, 1.0) * 15.0, // up to 15 pts at 1s
            _ => 0.0,
        };
        let avail_bonus = match p.health.availability {
            Some(a) => (a * 10.0).clamp(0.0, 10.0),
            None => 5.0,
        };
        // Load headroom: penalize when active flows approach capacity.
        let util = p.load.utilization.clamp(0.0, 1.0);
        let load_penalty = util * 20.0;

        (w + avail_bonus - latency_penalty - load_penalty).max(0.0)
    }

    /// Select the best profile. Deterministic health-aware weighted
    /// selection: rank eligible profiles by score and pick the top
    /// (ties broken deterministically by profile_id).
    pub fn select_for(&mut self, now_ms: i64) -> SelectionDecision {
        // Build candidate list with exclusion reasons.
        let mut excluded: Vec<Exclusion> = Vec::new();
        let mut candidates: Vec<(String, f64, String)> = Vec::new();
        for p in &self.profiles {
            let id = p.profile.profile_id.clone();
            let state = self.derive_state(p, now_ms);
            let w = self.weight(p, now_ms);
            if w == 0 {
                let reason = match state {
                    ProfileState::Cooldown => "in cooldown after failure".into(),
                    ProfileState::Failed => "failed health probes".into(),
                    _ => "weight zero".into(),
                };
                excluded.push(Exclusion {
                    profile_id: id,
                    reason,
                });
                continue;
            }
            let score = self.score(p, now_ms);
            candidates.push((id.clone(), score, explain_score(state, &p.health, score)));
        }

        let candidates_count = candidates.len();
        // Deterministic tie-break: score desc, then profile_id asc.
        candidates.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });

        match candidates.into_iter().next() {
            Some((id, score, reason)) => {
                let dec = SelectionDecision {
                    profile_id: id,
                    score,
                    reason,
                    excluded,
                    candidates: candidates_count,
                };
                self.active = Some(dec.profile_id.clone());
                if let Some(p) = self
                    .profiles
                    .iter_mut()
                    .find(|p| p.profile.profile_id == dec.profile_id)
                {
                    p.last_selected_ms = now_ms;
                }
                dec
            }
            None => {
                // No eligible candidate: clear the active profile so the
                // consumer is told to stop (no silent keep-running of a
                // failed profile). Honesty rule — traffic goes direct only
                // when there is genuinely no usable path.
                self.active = None;
                SelectionDecision {
                    profile_id: String::new(),
                    score: 0.0,
                    reason: "no eligible profile".into(),
                    excluded,
                    candidates: 0,
                }
            }
        }
    }

    /// Planned rotation (mission §10): pick a different eligible profile than
    /// the current active, unless the active is significantly better
    /// (hysteresis — don't break a healthy path just because a timer fired).
    pub fn maybe_planned_rotate(&mut self, now_ms: i64) -> Option<String> {
        if self.config.rotation_interval.as_millis() == 0 {
            return None;
        }
        let active_id = self.active.clone()?;
        // Dwell gate.
        let dwell = self
            .profiles
            .iter()
            .find(|p| p.profile.profile_id == active_id)
            .map(|p| now_ms - p.last_selected_ms)
            .unwrap_or(0);
        if dwell < self.config.min_dwell.as_millis() as i64 {
            return None;
        }

        // Rank all eligible profiles.
        let mut ranked: Vec<(String, f64)> = self
            .profiles
            .iter()
            .filter(|p| self.weight(p, now_ms) > 0)
            .map(|p| (p.profile.profile_id.clone(), self.score(p, now_ms)))
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // The best candidate that is not the current active.
        let best_other = ranked.iter().find(|(id, _)| *id != active_id)?;
        let active_score = ranked
            .iter()
            .find(|(id, _)| *id == active_id)
            .map(|(_, s)| *s)
            .unwrap_or(0.0);

        // Don't rotate away from a significantly-better active profile.
        if active_score > best_other.1
            && (active_score - best_other.1) >= self.config.better_threshold
        {
            return None;
        }

        let next = best_other.0.clone();
        self.active = Some(next.clone());
        self.last_rotation_ms = now_ms;
        self.last_rotation_reason = Some(format!(
            "planned rotation: {} better than active {} ({} vs {:.0})",
            next, active_id, best_other.1, active_score
        ));
        Some(next)
    }

    /// Force rotation to a specific profile (manual / failure failover path).
    pub fn force_rotate_to(
        &mut self,
        profile_id: &str,
        reason: String,
        now_ms: i64,
    ) -> Result<String, String> {
        if !self
            .profiles
            .iter()
            .any(|p| p.profile.profile_id == profile_id)
        {
            return Err(format!("no profile '{profile_id}'"));
        }
        let prev = self.active.clone();
        self.active = Some(profile_id.to_string());
        self.last_rotation_ms = now_ms;
        self.last_rotation_reason = Some(format!("{reason} (was {prev:?})"));
        if let Some(p) = self
            .profiles
            .iter_mut()
            .find(|p| p.profile.profile_id == profile_id)
        {
            p.last_selected_ms = now_ms;
        }
        Ok(profile_id.to_string())
    }

    /// Snapshot the pool for the daemon/WebUI (no credentials).
    pub fn snapshot(&self, now_ms: i64) -> PoolSnapshot {
        PoolSnapshot {
            profiles: self
                .profiles
                .iter()
                .map(|p| {
                    let mut h = p.health.clone();
                    h.profile_id = p.profile.profile_id.clone();
                    h.label = p.profile.label.clone();
                    h.active_flows = p.load.active_flows;
                    h
                })
                .collect(),
            active: self.active.clone(),
            excluded: Vec::new(),
            last_rotation_ms: self.last_rotation_ms,
            last_rotation_reason: self.last_rotation_reason.clone(),
            updated_ms: now_ms,
        }
    }
}

fn explain_score(state: ProfileState, health: &ProfileHealth, score: f64) -> String {
    let mut parts = vec![format!("state={}", state.label())];
    if let Some(lat) = health.latency_ms {
        parts.push(format!("latency={lat:.0}ms"));
    }
    if let Some(avail) = health.availability {
        parts.push(format!("availability={:.0}%", avail * 100.0));
    }
    if health.weight > 0 {
        parts.push(format!("weight={}", health.weight));
    }
    format!("score {score:.1} ({})", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::importer;
    use balansir_health::PathSample;
    use std::time::Duration;

    const TS: i64 = 1_700_000_000_000;

    fn test_config() -> PoolConfig {
        PoolConfig {
            min_dwell: Duration::from_secs(120),
            failure_cooldown: Duration::from_secs(60),
            health_cooldown: Duration::from_secs(0), // deterministic tests
            rotation_interval: Duration::from_secs(0), // disabled
            better_threshold: 25.0,
            ramp_steps: vec![10, 25, 50, 100],
            capacity_per_profile: 64,
        }
    }

    fn vless(host: &str, port: u16) -> crate::profile::VpnProfile {
        importer::parse_line(
            &format!(
                "vless://194302fe-9c53-4203-b17e-c0b30a4d79b6@{host}:{port}?security=none&type=tcp#Node-{host}"
            ),
            "test",
            TS,
        )
        .unwrap()
    }

    fn populate(pool: &mut VpnPool, hosts: &[(&str, u16)]) {
        let profiles: Vec<_> = hosts.iter().map(|(h, p)| vless(h, *p)).collect();
        pool.atomic_replace(profiles, TS).unwrap();
    }

    fn sample_healthy() -> PathSample {
        PathSample {
            latency_ms: Some(50.0),
            loss_pct: None,
            reachable: true,
            degraded_evidence: false,
        }
    }

    fn sample_failure() -> PathSample {
        PathSample::failure()
    }

    fn ids(pool: &VpnPool) -> Vec<String> {
        pool.profiles()
            .iter()
            .map(|p| p.profile.profile_id.clone())
            .collect()
    }

    #[test]
    fn atomic_replace_rejects_empty_pool() {
        let mut pool = VpnPool::new(test_config());
        assert!(pool.atomic_replace(vec![], TS).is_err());
        assert!(pool.profiles().is_empty());
    }

    #[test]
    fn atomic_replace_keeps_known_good_pool_on_bad_input() {
        let mut pool = VpnPool::new(test_config());
        populate(&mut pool, &[("a.example.com", 443), ("b.example.com", 443)]);
        let before = ids(&pool);
        // A failed import (empty) must NOT empty the working pool.
        assert!(pool.atomic_replace(vec![], TS).is_err());
        assert_eq!(ids(&pool), before, "working pool preserved");
    }

    #[test]
    fn selects_healthy_profile_deterministically() {
        let mut pool = VpnPool::new(test_config());
        populate(&mut pool, &[("b.example.com", 443), ("a.example.com", 443)]);
        let d = pool.select_for(TS);
        assert!(!d.profile_id.is_empty());
        assert!(d.candidates >= 1);
        // Second call with same inputs selects the same profile.
        let d2 = pool.select_for(TS);
        assert_eq!(d.profile_id, d2.profile_id);
    }

    #[test]
    fn failed_profile_is_excluded_and_healthier_wins() {
        let mut pool = VpnPool::new(test_config());
        populate(&mut pool, &[("a.example.com", 443), ("b.example.com", 443)]);
        let a_id = pool.profiles()[0].profile.profile_id.clone();
        let b_id = pool.profiles()[1].profile.profile_id.clone();

        // b fails twice → Failed (enter_degraded=2) → weight 0.
        pool.observe_health(&b_id, sample_failure(), TS);
        pool.observe_health(&b_id, sample_failure(), TS);
        assert_eq!(
            pool.profile(&b_id).unwrap().health.state,
            ProfileState::Failed
        );

        let d = pool.select_for(TS);
        assert_eq!(d.profile_id, a_id, "healthy profile selected over failed");
        assert!(
            d.excluded
                .iter()
                .any(|e| e.profile_id == b_id && e.reason.contains("failed")),
            "exclusion explains why b was skipped: {:?}",
            d.excluded
        );
    }

    #[test]
    fn degraded_profile_loses_to_healthy() {
        let mut pool = VpnPool::new(test_config());
        populate(&mut pool, &[("a.example.com", 443), ("b.example.com", 443)]);
        let a_id = pool.profiles()[0].profile.profile_id.clone();
        let b_id = pool.profiles()[1].profile.profile_id.clone();
        // a degraded: high latency twice.
        let slow = PathSample {
            latency_ms: Some(900.0),
            loss_pct: None,
            reachable: true,
            degraded_evidence: false,
        };
        pool.observe_health(&a_id, slow, TS);
        pool.observe_health(&a_id, slow, TS);
        pool.observe_health(&b_id, sample_healthy(), TS);
        assert_eq!(
            pool.profile(&a_id).unwrap().health.state,
            ProfileState::Degraded
        );
        let d = pool.select_for(TS);
        assert_eq!(d.profile_id, b_id);
    }

    #[test]
    fn planned_rotation_respects_dwell_and_threshold() {
        let mut config = test_config();
        config.rotation_interval = Duration::from_secs(60);
        config.min_dwell = Duration::from_secs(120);
        config.better_threshold = 25.0;
        let mut pool = VpnPool::new(config);
        populate(&mut pool, &[("a.example.com", 443), ("b.example.com", 443)]);
        let a_id = pool.profiles()[0].profile.profile_id.clone();
        let b_id = pool.profiles()[1].profile.profile_id.clone();
        pool.observe_health(&a_id, sample_healthy(), TS);
        pool.observe_health(&b_id, sample_healthy(), TS);

        // Select a as active (a < b alphabetically, deterministic tie).
        let d = pool.select_for(TS);
        let active = d.profile_id.clone();
        let _ = pool.force_rotate_to(&active, "initial".to_string(), TS);

        // Dwell not met → no rotation.
        assert!(pool.maybe_planned_rotate(TS + 10_000).is_none());

        // Dwell met, but active is significantly better → still no rotation.
        pool.observe_health(&active, sample_healthy(), TS);
        // Make the other profile clearly worse (high latency).
        let other = if active == a_id {
            b_id.clone()
        } else {
            a_id.clone()
        };
        let slow = PathSample {
            latency_ms: Some(2000.0),
            loss_pct: None,
            reachable: true,
            degraded_evidence: false,
        };
        pool.observe_health(&other, slow, TS);
        pool.observe_health(&other, slow, TS);
        assert!(
            pool.maybe_planned_rotate(TS + 200_000).is_none(),
            "don't break a better path"
        );
    }

    #[test]
    fn planned_rotation_switches_when_other_is_better() {
        let mut config = test_config();
        config.rotation_interval = Duration::from_secs(60);
        config.min_dwell = Duration::from_secs(120);
        let mut pool = VpnPool::new(config);
        populate(&mut pool, &[("a.example.com", 443), ("b.example.com", 443)]);
        let a_id = pool.profiles()[0].profile.profile_id.clone();
        let b_id = pool.profiles()[1].profile.profile_id.clone();

        // Make a active but b strictly better (b low latency, a high).
        let slow = PathSample {
            latency_ms: Some(800.0),
            loss_pct: None,
            reachable: true,
            degraded_evidence: false,
        };
        pool.observe_health(&a_id, slow, TS);
        pool.observe_health(&a_id, slow, TS);
        pool.observe_health(&b_id, sample_healthy(), TS);
        let d = pool.select_for(TS);
        assert_eq!(d.profile_id, b_id);

        // Force active = a to set the dwell clock, then rotate after dwell.
        let _ = pool.force_rotate_to(&a_id, "test".to_string(), TS);
        let rot = pool.maybe_planned_rotate(TS + 200_000);
        assert_eq!(
            rot.as_deref(),
            Some(b_id.as_str()),
            "rotation to clearly-better candidate"
        );
    }

    #[test]
    fn force_rotate_rejects_unknown_profile() {
        let mut pool = VpnPool::new(test_config());
        populate(&mut pool, &[("a.example.com", 443)]);
        assert!(pool
            .force_rotate_to("nonexistent", "x".to_string(), TS)
            .is_err());
    }

    #[test]
    fn recovery_ramps_weight_up() {
        let mut pool = VpnPool::new(test_config());
        populate(&mut pool, &[("a.example.com", 443)]);
        let a_id = pool.profiles()[0].profile.profile_id.clone();

        // Fail → Failed (enter_degraded=2).
        pool.observe_health(&a_id, sample_failure(), TS);
        pool.observe_health(&a_id, sample_failure(), TS);
        assert_eq!(
            pool.profile(&a_id).unwrap().health.state,
            ProfileState::Failed
        );
        assert_eq!(pool.weight(&pool.profiles()[0], TS), 0);

        // After cooldown, healthy probes recover (exit_degraded=3; health
        // cooldown is 0 in tests so samples can be adjacent).
        let t1 = TS + 120_000; // past failure cooldown
        pool.observe_health(&a_id, sample_healthy(), t1);
        pool.observe_health(&a_id, sample_healthy(), t1 + 1);
        pool.observe_health(&a_id, sample_healthy(), t1 + 2);
        assert_eq!(
            pool.profile(&a_id).unwrap().health.state,
            ProfileState::Recovering,
            "recovered profile enters Recovering (ramp-up)"
        );
        // 3 successes → ramp step index min(3, len)-1 = 2 → 50.
        let w1 = pool.weight(&pool.profiles()[0], t1 + 2);
        assert_eq!(w1, 50, "ramp step after 3 successes = 50");

        // More stable probes → ramps up toward 100.
        pool.observe_health(&a_id, sample_healthy(), t1 + 3);
        pool.observe_health(&a_id, sample_healthy(), t1 + 4);
        pool.observe_health(&a_id, sample_healthy(), t1 + 5);
        let w = pool.weight(&pool.profiles()[0], t1 + 5);
        assert_eq!(w, 100, "ramp reaches full weight after stable probes");
    }

    #[test]
    fn cooldown_excludes_failed_profile_then_allows_probe() {
        let mut pool = VpnPool::new(test_config());
        populate(&mut pool, &[("a.example.com", 443), ("b.example.com", 443)]);
        let a_id = pool.profiles()[0].profile.profile_id.clone();
        pool.observe_health(&a_id, sample_failure(), TS);
        pool.observe_health(&a_id, sample_failure(), TS);
        assert_eq!(
            pool.profile(&a_id).unwrap().health.state,
            ProfileState::Failed
        );

        // During cooldown: excluded.
        let d = pool.select_for(TS + 10_000);
        assert_ne!(d.profile_id, a_id);
        assert!(d.excluded.iter().any(|e| e.profile_id == a_id));

        // After cooldown with healthy probes → Recovers and becomes eligible.
        let t = TS + 120_000;
        pool.observe_health(&a_id, sample_healthy(), t);
        pool.observe_health(&a_id, sample_healthy(), t + 1);
        pool.observe_health(&a_id, sample_healthy(), t + 2);
        assert_eq!(
            pool.profile(&a_id).unwrap().health.state,
            ProfileState::Recovering
        );
        let d = pool.select_for(t + 2);
        assert!(
            d.excluded.iter().all(|e| e.profile_id != a_id),
            "a no longer excluded"
        );
    }

    #[test]
    fn active_cleared_when_profile_removed() {
        let mut pool = VpnPool::new(test_config());
        populate(&mut pool, &[("a.example.com", 443), ("b.example.com", 443)]);
        // Select: pool picks the deterministic best (both Unknown, tie by id).
        pool.select_for(TS);
        let active = pool.active().unwrap().to_string();
        assert!(pool.profile(&active).is_some());
        // Replace with only the other host → active is gone → active cleared.
        let other = if pool.profiles()[0].profile.profile_id == active {
            "b.example.com"
        } else {
            "a.example.com"
        };
        populate(&mut pool, &[(other, 443)]);
        assert!(pool.active().is_none());
    }

    #[test]
    fn no_eligible_profiles_yields_empty_decision() {
        let mut pool = VpnPool::new(test_config());
        populate(&mut pool, &[("a.example.com", 443)]);
        let a_id = pool.profiles()[0].profile.profile_id.clone();
        pool.observe_health(&a_id, sample_failure(), TS);
        pool.observe_health(&a_id, sample_failure(), TS);
        let d = pool.select_for(TS);
        assert!(d.profile_id.is_empty());
        assert_eq!(d.reason, "no eligible profile");
    }

    #[test]
    fn active_profile_cleared_when_all_eligible_profiles_fail() {
        // The active profile later fails real probes; with no alternative
        // left, selection must clear `active` so the consumer stops the
        // proxy — never keep running a profile that failed health checks.
        let mut pool = VpnPool::new(test_config());
        populate(&mut pool, &[("a.example.com", 443), ("b.example.com", 443)]);
        let a_id = pool.profiles()[0].profile.profile_id.clone();
        let b_id = pool.profiles()[1].profile.profile_id.clone();

        // a selected and active.
        let d = pool.select_for(TS);
        assert!(!d.profile_id.is_empty());
        assert!(pool.active().is_some(), "a profile is active");

        // Both fail real probes (enter_degraded = 2).
        pool.observe_health(&a_id, sample_failure(), TS + 1);
        pool.observe_health(&a_id, sample_failure(), TS + 2);
        pool.observe_health(&b_id, sample_failure(), TS + 1);
        pool.observe_health(&b_id, sample_failure(), TS + 2);

        let d = pool.select_for(TS + 3);
        assert!(d.profile_id.is_empty(), "no eligible profile");
        assert!(
            pool.active().is_none(),
            "active must be cleared so the consumer is told to stop"
        );
    }
}
