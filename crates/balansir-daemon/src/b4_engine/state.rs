//! B4 runtime loop and state machine (P7.1, ADR-024).
//!
//! The engine proves the **B4 runtime loop**:
//!
//! ```text
//! observe → classify → adapt (MTU / DNS-path) → re-observe → recover / strict-fail
//! ```
//!
//! It is pure with respect to I/O: observations come in via the `B4Observer`,
//! and decisions come out as `B4Decision`s for the daemon to execute. The
//! engine never owns a connection, never performs I/O, and never decides what
//! *should* be (that is policy). It only decides *how to deliver a flow the
//! policy already admitted*.

use crate::b4_engine::classify::{classify, B4Class};
use crate::b4_engine::observe::{B4Observation, B4Observer};
use crate::b4_engine::policy::{B4Capability, B4FailSemantic, B4Policy, B4Profile};

/// Per-flow B4 lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum B4State {
    /// No observation yet for this flow.
    Idle,
    /// Collecting host-stack signals.
    Observing,
    /// Applying an adaptation (MTU / DNS-path).
    Adapting,
    /// Monitoring after an adaptation to verify recovery.
    Monitoring,
    /// Recovered: the adapted direct path is healthy.
    Recovered,
    /// A restricted fallback (per policy) is in use.
    Fallback,
    /// Strict fail: no secure mechanism, flow must not bypass.
    StrictFail,
}

/// A decision the engine hands to the daemon. The daemon executes it; B4 does
/// not. This keeps B4 a mechanism-selector under policy, never an authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum B4Decision {
    /// Nothing to do for this flow this cycle.
    Noop,
    /// Adjust the effective MTU/MSS for the flow's direct path.
    AdaptMtu { mtu: u16 },
    /// Prefer a different DNS path for the flow's domain.
    SwitchDnsPath,
    /// Use a restricted fallback (only allowed when policy permits).
    UseFallback,
    /// Strict fail: the flow must fail, not silently bypass.
    FailStrict,
    /// Recovered: direct path is healthy, no adaptation needed.
    Recovered,
}

/// Observability event emitted per flow-cycle (metrics/decision trace hook).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum B4Event {
    Classified {
        flow: String,
        class: B4Class,
    },
    Adapted {
        flow: String,
        capability: B4Capability,
    },
    Recovered {
        flow: String,
    },
    StrictFailed {
        flow: String,
    },
}

/// Per-flow bookkeeping kept by the engine. Deliberately *not* a session or
/// connection: it is a small adaptation-context record, in-memory only.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FlowContext {
    state: B4State,
    /// Current best guess of the effective MTU (set by an MTU adaptation).
    mtu: Option<u16>,
    /// How many consecutive adaptation rounds we have attempted.
    attempts: u32,
}

impl Default for FlowContext {
    fn default() -> Self {
        Self {
            state: B4State::Idle,
            mtu: None,
            attempts: 0,
        }
    }
}

/// Configuration for the engine's bounded runtime.
#[derive(Debug, Clone, Copy)]
pub struct B4EngineConfig {
    /// Maximum consecutive adaptation attempts before strict-fail/fallback.
    pub max_attempts: u32,
    /// Whether B4 adaptation is enabled at all (default on).
    pub enabled: bool,
}

impl Default for B4EngineConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            enabled: true,
        }
    }
}

/// The B4 runtime loop engine (P7.1).
///
/// Constructed with the daemon's B4 policy and an injected observer. Each
/// `evaluate(flow_key)` performs one loop iteration for that flow and returns
/// a `B4Decision` + a list of observability `B4Event`s.
pub struct B4Engine {
    policy: B4Policy,
    observer: std::sync::Arc<dyn B4Observer>,
    config: B4EngineConfig,
    flows: std::collections::HashMap<String, FlowContext>,
    /// Last emitted decision per flow (for `explain`-style introspection).
    last_decisions: std::collections::HashMap<String, B4Decision>,
    /// Last host-stack observation per flow (for health introspection).
    last_observations: std::collections::HashMap<String, B4Observation>,
}

impl B4Engine {
    pub fn new(policy: B4Policy, observer: std::sync::Arc<dyn B4Observer>) -> Self {
        Self::with_config(policy, observer, B4EngineConfig::default())
    }

    pub fn with_config(
        policy: B4Policy,
        observer: std::sync::Arc<dyn B4Observer>,
        config: B4EngineConfig,
    ) -> Self {
        Self {
            policy,
            observer,
            config,
            flows: std::collections::HashMap::new(),
            last_decisions: std::collections::HashMap::new(),
            last_observations: std::collections::HashMap::new(),
        }
    }

    /// The current B4 state for a flow (introspection / tests).
    pub fn state_of(&self, flow: &str) -> B4State {
        self.flows
            .get(flow)
            .map(|c| c.state)
            .unwrap_or(B4State::Idle)
    }

    /// Mark a flow as Adapting (used by the controller for DNS-path adaptation).
    pub fn mark_adapting(&mut self, flow: &str) {
        if let Some(ctx) = self.flows.get_mut(flow) {
            ctx.state = B4State::Adapting;
        }
    }

    /// The last decision for a flow (introspection / explain).
    pub fn last_decision(&self, flow: &str) -> Option<&B4Decision> {
        self.last_decisions.get(flow)
    }

    /// The last host-stack observation for a flow (health introspection).
    pub fn last_observation(&self, flow: &str) -> Option<&B4Observation> {
        self.last_observations.get(flow)
    }

    /// The number of distinct flows the engine is tracking.
    pub fn tracked_flows(&self) -> usize {
        self.flows.len()
    }

    /// The flow keys the engine has observed.
    pub fn flow_keys(&self) -> Vec<String> {
        self.flows.keys().cloned().collect()
    }

    /// The domains the engine's policy knows about (for pre-seeding the loop).
    pub fn policy_domains(&self) -> Vec<String> {
        self.policy.flow_domains()
    }

    /// Run the B4 loop forever (P7.1): every `interval_secs`, evaluate each
    /// known flow and execute the decision via `executor`.
    ///
    /// `executor` is a callback the daemon supplies to apply a `B4Decision`
    /// (e.g. set MTU, switch DNS path). The engine itself never performs I/O.
    pub async fn run_loop<F, Fut>(&mut self, interval_secs: u64, mut executor: F) -> !
    where
        F: FnMut(String, B4Decision) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            let flows: Vec<String> = self.flow_keys();
            // Also evaluate the configured flows even if not yet observed, so
            // a policy that has never produced an observation is still probed.
            for f in self.policy.flow_domains() {
                if !flows.contains(&f) {
                    self.flows.entry(f.clone()).or_default();
                }
            }
            let keys: Vec<String> = self.flow_keys();
            for flow in keys {
                let (decision, _events) = self.evaluate(&flow).await;
                executor(flow.clone(), decision).await;
            }
        }
    }

    /// Run one loop iteration for a flow: observe, classify, and decide.
    ///
    /// The flow key is the domain (as the policy table keys on domains). If
    /// adaptation is disabled, the engine only classifies and reports.
    pub async fn evaluate(&mut self, flow: &str) -> (B4Decision, Vec<B4Event>) {
        let profile = self.policy.profile_for(flow);
        let obs = self.observer.observe(flow).await;
        let class = classify(&obs);

        if !self.config.enabled {
            let events = vec![B4Event::Classified {
                flow: flow.to_string(),
                class,
            }];
            return (B4Decision::Noop, events);
        }

        let mut events = vec![B4Event::Classified {
            flow: flow.to_string(),
            class,
        }];
        let (decision, mut decision_events) = self.decide(flow, &profile, class, &obs);
        for ev in &mut decision_events {
            if let B4Event::Adapted { flow: f, .. } | B4Event::StrictFailed { flow: f } = ev {
                if f.is_empty() {
                    *f = flow.to_string();
                }
            }
        }
        events.append(&mut decision_events);
        self.last_decisions
            .insert(flow.to_string(), decision.clone());
        self.last_observations.insert(flow.to_string(), obs);
        (decision, events)
    }

    fn decide(
        &mut self,
        flow: &str,
        profile: &B4Profile,
        class: B4Class,
        obs: &B4Observation,
    ) -> (B4Decision, Vec<B4Event>) {
        let ctx = self.flows.entry(flow.to_string()).or_default();
        let max_attempts = self.config.max_attempts;

        match class {
            B4Class::Direct => {
                ctx.state = B4State::Recovered;
                ctx.attempts = 0;
                (B4Decision::Recovered, vec![])
            }
            B4Class::Unknown => {
                ctx.state = B4State::Observing;
                (B4Decision::Noop, vec![])
            }
            B4Class::Degraded | B4Class::Interfered => Self::adapt(ctx, profile, obs, max_attempts),
            B4Class::Blocked => Self::recover(ctx, profile),
        }
    }

    /// Choose an adaptation within the policy's allowed capabilities.
    fn adapt(
        ctx: &mut FlowContext,
        profile: &B4Profile,
        obs: &B4Observation,
        max_attempts: u32,
    ) -> (B4Decision, Vec<B4Event>) {
        ctx.state = B4State::Adapting;
        ctx.attempts += 1;

        if ctx.attempts > max_attempts {
            return Self::recover(ctx, profile);
        }

        // MTU adaptation is preferred (the first vertical slice mechanism):
        // reduce the effective MTU when an MTU symptom is observed.
        if obs.mtu_symptom == Some(true) && profile.capabilities.contains(&B4Capability::Mtu) {
            let current = ctx.mtu.unwrap_or(1500);
            let new_mtu = if current > 1280 {
                current - 20
            } else {
                current
            };
            ctx.mtu = Some(new_mtu);
            ctx.state = B4State::Monitoring;
            return (
                B4Decision::AdaptMtu { mtu: new_mtu },
                vec![B4Event::Adapted {
                    flow: String::new(),
                    capability: B4Capability::Mtu,
                }],
            );
        }

        // DNS-path adaptation as a second allowed mechanism.
        if obs.dns_ok == Some(false) && profile.capabilities.contains(&B4Capability::DnsPath) {
            ctx.state = B4State::Monitoring;
            return (
                B4Decision::SwitchDnsPath,
                vec![B4Event::Adapted {
                    flow: String::new(),
                    capability: B4Capability::DnsPath,
                }],
            );
        }

        Self::recover(ctx, profile)
    }

    /// Recovery within policy bounds: fallback only if allowed, else strict
    /// fail (never a silent downgrade).
    fn recover(ctx: &mut FlowContext, profile: &B4Profile) -> (B4Decision, Vec<B4Event>) {
        // Restricted fallback is only ever chosen when policy explicitly
        // allows it. A tunnel is a last resort, not the default.
        if profile.allow_tunnel {
            ctx.state = B4State::Fallback;
            return (B4Decision::UseFallback, vec![]);
        }
        if profile.allow_direct && profile.fail != B4FailSemantic::Strict {
            ctx.state = B4State::Fallback;
            return (B4Decision::UseFallback, vec![]);
        }
        // Strict (default) and no allowed fallback: fail the flow, never
        // silently bypass.
        ctx.state = B4State::StrictFail;
        (
            B4Decision::FailStrict,
            vec![B4Event::StrictFailed {
                flow: String::new(),
            }],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b4_engine::policy::B4Profile;
    use std::sync::Arc;
    use std::time::Duration;

    /// An observer with a controllable signal per flow.
    struct StubObserver {
        signal: std::sync::Mutex<std::collections::HashMap<String, B4Observation>>,
    }
    impl StubObserver {
        fn new() -> Self {
            Self {
                signal: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
        fn set(&self, flow: &str, obs: B4Observation) {
            self.signal
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(flow.to_string(), obs);
        }
    }
    #[async_trait::async_trait]
    impl B4Observer for StubObserver {
        async fn observe(&self, flow: &str) -> B4Observation {
            self.signal
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(flow)
                .copied()
                .unwrap_or_default()
        }
    }

    fn policy_with(profile: B4Profile) -> B4Policy {
        B4Policy {
            flows: vec![crate::b4_engine::policy::B4FlowRule {
                domain: "example.com".into(),
                profile,
            }],
        }
    }

    #[tokio::test]
    async fn healthy_flow_is_recovered() {
        let obs = B4Observation {
            rtt: Some(Duration::from_millis(20)),
            ..Default::default()
        };
        let observer = Arc::new(StubObserver::new());
        observer.set("example.com", obs);
        let mut engine = B4Engine::new(policy_with(B4Profile::default()), observer);
        let (decision, _) = engine.evaluate("example.com").await;
        assert_eq!(decision, B4Decision::Recovered);
        assert_eq!(engine.state_of("example.com"), B4State::Recovered);
    }

    #[tokio::test]
    async fn mtu_symptom_triggers_mtu_adaptation() {
        let obs = B4Observation {
            mtu_symptom: Some(true),
            ..Default::default()
        };
        let observer = Arc::new(StubObserver::new());
        observer.set("example.com", obs);
        let policy = policy_with(B4Profile {
            capabilities: vec![B4Capability::Mtu],
            ..Default::default()
        });
        let mut engine = B4Engine::new(policy, observer);
        let (decision, _) = engine.evaluate("example.com").await;
        assert!(matches!(decision, B4Decision::AdaptMtu { mtu } if mtu == 1480));
        assert_eq!(engine.state_of("example.com"), B4State::Monitoring);
    }

    #[tokio::test]
    async fn blocked_strict_flow_fails_rather_than_bypass() {
        let obs = B4Observation {
            reset_or_timeout: Some(true),
            ..Default::default()
        };
        let observer = Arc::new(StubObserver::new());
        observer.set("blocked.example.com", obs);
        let mut engine = B4Engine::new(policy_with(B4Profile::default()), observer);
        let (decision, _) = engine.evaluate("blocked.example.com").await;
        assert_eq!(decision, B4Decision::FailStrict);
        assert_eq!(engine.state_of("blocked.example.com"), B4State::StrictFail);
    }

    #[tokio::test]
    async fn safe_flow_with_direct_allowed_uses_restricted_fallback() {
        let obs = B4Observation {
            reset_or_timeout: Some(true),
            ..Default::default()
        };
        let observer = Arc::new(StubObserver::new());
        observer.set("safe.example.com", obs);
        let policy = policy_with(B4Profile {
            fail: B4FailSemantic::Safe,
            allow_direct: true,
            ..Default::default()
        });
        let mut engine = B4Engine::new(policy, observer);
        let (decision, _) = engine.evaluate("safe.example.com").await;
        assert_eq!(decision, B4Decision::UseFallback);
        assert_eq!(engine.state_of("safe.example.com"), B4State::Fallback);
    }

    #[tokio::test]
    async fn disabled_engine_only_classifies() {
        let obs = B4Observation {
            mtu_symptom: Some(true),
            ..Default::default()
        };
        let observer = Arc::new(StubObserver::new());
        observer.set("example.com", obs);
        let policy = policy_with(B4Profile {
            capabilities: vec![B4Capability::Mtu],
            ..Default::default()
        });
        let mut engine = B4Engine::with_config(
            policy,
            observer,
            B4EngineConfig {
                enabled: false,
                ..Default::default()
            },
        );
        let (decision, events) = engine.evaluate("example.com").await;
        assert_eq!(decision, B4Decision::Noop);
        assert!(events
            .iter()
            .any(|e| matches!(e, B4Event::Classified { .. })));
    }
}
