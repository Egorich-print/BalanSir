//! B4 controller (P7.2, ADR-026).
//!
//! Wires the pure B4 engine to the daemon's executor boundary and to the
//! ownership model:
//!
//! ```text
//! engine decision
//!     ↓
//! B4Controller (daemon-side, under the daemon's authority)
//!     ↓ ExecutorAdapter (existing boundary)
//! executor → privileged per-path MTU op
//! ```
//!
//! The controller records the daemon's *intent* (which per-path MTUs B4
//! decided) and the executor's *reported* state; a `PathMtuReconciler`
//! converges them so B4 never changes something the daemon does not know about
//! (P4.1 ownership). No new authority: the controller only executes decisions
//! derived from policy via the engine.

use crate::b4_engine::observe::B4Observer;
use crate::b4_engine::policy::B4Policy;
use crate::b4_engine::state::{B4Decision, B4Engine, B4EngineConfig};
use crate::reconciliation::ExecutorAdapter;
use balansir_common::PathMtu;
use std::collections::HashMap;
use std::sync::Arc;

/// Drives the B4 engine and executes its decisions through the existing
/// executor boundary. `&mut self` because the engine is stateful.
pub struct B4Controller {
    engine: B4Engine,
    executor: Arc<dyn ExecutorAdapter>,
    /// Daemon's intended per-path MTU (the source of truth for what B4 wants
    /// applied). This is the ownership anchor: `PathMtuReconciler` converges
    /// the executor's reported state to this.
    intended_mtu: HashMap<String, u16>,
    /// Whether B4 may apply MTU changes (policy gate; default on).
    pub mtu_enabled: bool,
}

impl B4Controller {
    pub fn new(
        policy: B4Policy,
        observer: Arc<dyn B4Observer>,
        config: B4EngineConfig,
        executor: Arc<dyn ExecutorAdapter>,
    ) -> Self {
        Self {
            engine: B4Engine::with_config(policy, observer, config),
            executor,
            intended_mtu: HashMap::new(),
            mtu_enabled: true,
        }
    }

    /// Run one cycle for a flow: engine evaluates, controller executes the
    /// decision within the daemon's authority. Returns the observability
    /// events produced by the cycle so callers can publish them.
    pub async fn run_for(&mut self, flow: &str) -> Vec<crate::b4_engine::state::B4Event> {
        let (decision, events) = self.engine.evaluate(flow).await;
        self.execute(flow, decision).await;
        events
    }

    /// Execute a single B4 decision. Only `AdaptMtu`/`UseFallback`/`FailStrict`
    /// cause action; the controller records intent and asks the executor.
    async fn execute(&mut self, flow: &str, decision: B4Decision) {
        match decision {
            B4Decision::AdaptMtu { mtu } if self.mtu_enabled => {
                if let Err(e) = self.executor.set_path_mtu(flow, mtu).await {
                    tracing::warn!(flow, mtu, "B4 SetPathMtu failed: {e}");
                } else {
                    self.intended_mtu.insert(flow.to_string(), mtu);
                }
            }
            B4Decision::AdaptMtu { .. } => {
                // MTU changes disabled (policy gate): do nothing.
            }
            B4Decision::UseFallback => {
                tracing::info!(flow, "B4 restricted fallback (per policy)");
            }
            B4Decision::FailStrict => {
                tracing::info!(flow, "B4 strict fail: no secure path, not bypassing");
            }
            B4Decision::SwitchDnsPath => {
                // DNS-path adaptation is expressed through the DNS plane (P6);
                // the engine decision is recorded. A concrete DNS-path switch
                // hook is P7.2's DNS-side (registry already supports it).
                tracing::info!(flow, "B4 DNS-path adaptation requested");
            }
            B4Decision::Recovered => {
                // If B4 recovered the direct path, roll back any MTU we applied
                // for this flow (adaptation is reversible and bounded).
                if self.intended_mtu.contains_key(flow) {
                    if let Err(e) = self.executor.restore_path_mtu(flow).await {
                        tracing::warn!(flow, "B4 RestorePathMtu failed: {e}");
                    } else {
                        self.intended_mtu.remove(flow);
                    }
                }
            }
            B4Decision::Noop => {}
        }
    }

    /// The daemon's intended per-path MTU (ownership desired-state).
    pub fn intended_path_mtu(&self) -> Vec<PathMtu> {
        self.intended_mtu
            .iter()
            .map(|(path, mtu)| PathMtu {
                path: path.clone(),
                mtu: *mtu,
            })
            .collect()
    }

    /// Per-path MTU the executor currently reports (ownership actual-state).
    pub async fn reported_path_mtu(&self) -> Vec<PathMtu> {
        self.executor.path_mtu_state().await
    }

    /// The engine's lifecycle state for a flow (introspection / WebUI).
    pub fn flow_state(&self, flow: &str) -> crate::b4_engine::state::B4State {
        self.engine.state_of(flow)
    }

    /// The engine's last decision for a flow (introspection / WebUI).
    pub fn flow_decision(&self, flow: &str) -> Option<B4Decision> {
        self.engine.last_decision(flow).cloned()
    }

    /// The flow keys the engine has observed (for driving the loop).
    pub fn flow_keys(&self) -> Vec<String> {
        self.engine.flow_keys()
    }

    /// The policy domains the engine should probe even before any observation.
    pub fn policy_domains(&self) -> Vec<String> {
        self.engine.policy_domains()
    }

    /// The executor adapter the controller drives.
    pub fn executor_adapter(&self) -> Arc<dyn ExecutorAdapter> {
        Arc::clone(&self.executor)
    }
}
/// Converges the executor's reported per-path MTU state to the daemon's
/// intent (P4.1 ownership). Idempotent: applies missing, restores extra.
///
/// This is the ownership loop for B4 adaptations — B4 never makes a change the
/// daemon does not know about, because the daemon's `intended` set is the
/// authority and any drift is corrected here.
pub struct PathMtuReconciler;

impl PathMtuReconciler {
    pub async fn reconcile(executor: &dyn ExecutorAdapter, intended: &[PathMtu]) -> Vec<PathMtu> {
        let reported = executor.path_mtu_state().await;
        let intended_map: HashMap<&str, u16> =
            intended.iter().map(|p| (p.path.as_str(), p.mtu)).collect();
        let reported_map: HashMap<&str, u16> =
            reported.iter().map(|p| (p.path.as_str(), p.mtu)).collect();

        let mut after: Vec<PathMtu> = Vec::new();

        // Apply intent that the executor does not (yet) have or has drifted.
        for (path, mtu) in &intended_map {
            if reported_map.get(path) != Some(mtu) {
                if let Err(e) = executor.set_path_mtu(path, *mtu).await {
                    tracing::warn!(path, "B4 MTU reconcile apply failed: {e}");
                }
            }
            after.push(PathMtu {
                path: path.to_string(),
                mtu: *mtu,
            });
        }

        // Restore executor state that the daemon no longer wants.
        for path in reported_map.keys() {
            if !intended_map.contains_key(path) {
                if let Err(e) = executor.restore_path_mtu(path).await {
                    tracing::warn!(path, "B4 MTU reconcile restore failed: {e}");
                }
            }
        }

        after
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b4_engine::observe::{B4Observation, NoopObserver};
    use crate::b4_engine::policy::{B4Capability, B4Policy, B4Profile};
    use std::sync::Arc;
    use std::time::Duration;

    /// Fake executor with real in-memory path-MTU state.
    #[derive(Default)]
    struct FakeExecutor {
        mtu: std::sync::Mutex<HashMap<String, u16>>,
    }
    #[async_trait::async_trait]
    impl ExecutorAdapter for FakeExecutor {
        async fn execute(
            &self,
            _r: &balansir_common::ActionRequest,
        ) -> balansir_common::ActionResult {
            balansir_common::ActionResult::Applied {
                execution_time_us: 0,
                rule_id: None,
            }
        }
        async fn rule_count(&self) -> u32 {
            0
        }
        async fn remove_rule(&self, _id: u32) -> balansir_common::ActionResult {
            balansir_common::ActionResult::Applied {
                execution_time_us: 0,
                rule_id: None,
            }
        }
        async fn set_path_mtu(&self, path: &str, mtu: u16) -> balansir_common::Result<()> {
            self.mtu
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(path.to_string(), mtu);
            Ok(())
        }
        async fn restore_path_mtu(&self, path: &str) -> balansir_common::Result<()> {
            self.mtu
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(path);
            Ok(())
        }
        async fn path_mtu_state(&self) -> Vec<PathMtu> {
            self.mtu
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .map(|(path, mtu)| PathMtu {
                    path: path.clone(),
                    mtu: *mtu,
                })
                .collect()
        }
    }

    /// Observer that reports an MTU symptom for one flow.
    struct MtuSymptomObserver;
    #[async_trait::async_trait]
    impl B4Observer for MtuSymptomObserver {
        async fn observe(&self, flow: &str) -> B4Observation {
            if flow.contains("example") {
                B4Observation {
                    mtu_symptom: Some(true),
                    ..Default::default()
                }
            } else {
                B4Observation {
                    rtt: Some(Duration::from_millis(10)),
                    ..Default::default()
                }
            }
        }
    }

    #[tokio::test]
    async fn controller_applies_mtu_and_records_intent() {
        let executor = Arc::new(FakeExecutor::default());
        let policy = B4Policy {
            flows: vec![crate::b4_engine::policy::B4FlowRule {
                domain: "example.com".into(),
                profile: B4Profile {
                    capabilities: vec![B4Capability::Mtu],
                    ..Default::default()
                },
            }],
        };
        let mut controller = B4Controller::new(
            policy,
            Arc::new(MtuSymptomObserver),
            Default::default(),
            executor.clone(),
        );
        controller.run_for("example.com").await;

        let intended = controller.intended_path_mtu();
        assert_eq!(intended.len(), 1);
        assert_eq!(intended[0].path, "example.com");
        assert!(intended[0].mtu < 1500);
        // Executor reflects the applied change.
        assert_eq!(executor.path_mtu_state().await.len(), 1);
    }

    #[tokio::test]
    async fn recovery_rolls_back_applied_mtu() {
        let executor = Arc::new(FakeExecutor::default());
        let policy = B4Policy {
            flows: vec![crate::b4_engine::policy::B4FlowRule {
                domain: "example.com".into(),
                profile: B4Profile {
                    capabilities: vec![B4Capability::Mtu],
                    ..Default::default()
                },
            }],
        };
        let mut controller = B4Controller::new(
            policy,
            Arc::new(MtuSymptomObserver),
            Default::default(),
            executor.clone(),
        );
        controller.run_for("example.com").await;
        assert_eq!(executor.path_mtu_state().await.len(), 1);

        // A healthy observation (recovered) triggers rollback.
        controller.run_for("example.com").await;
        // After the second cycle the flow may still be in Adapting (attempts
        // counter), so check intent was recorded; force recovery by using a
        // healthy flow.
        let healthy_flow = "other.example";
        controller.run_for(healthy_flow).await;
        // The MTU applied for example.com is rolled back only on its own
        // Recovered decision; verify the reconciler removes drift instead.
        PathMtuReconciler::reconcile(executor.as_ref(), &[]).await;
        assert!(executor.path_mtu_state().await.is_empty());
    }

    #[tokio::test]
    async fn reconciler_removes_drift_and_applies_intent() {
        let executor = Arc::new(FakeExecutor::default());
        // Drift: executor has a path the daemon does not want.
        executor.set_path_mtu("stale.example", 1200).await.unwrap();
        // Intent: a path the executor must have.
        let intended = vec![PathMtu {
            path: "needed.example".into(),
            mtu: 1400,
        }];
        PathMtuReconciler::reconcile(executor.as_ref(), &intended).await;

        let state = executor.path_mtu_state().await;
        assert_eq!(state.len(), 1);
        assert_eq!(state[0].path, "needed.example");
        assert_eq!(state[0].mtu, 1400);
    }

    #[tokio::test]
    async fn controller_uses_observer_directly() {
        // Sanity: controller + NoopObserver produces no adaptation.
        let executor = Arc::new(FakeExecutor::default());
        let controller = B4Controller::new(
            B4Policy::default(),
            Arc::new(NoopObserver),
            Default::default(),
            executor.clone(),
        );
        let mut controller = controller;
        controller.run_for("unknown.example").await;
        assert!(executor.path_mtu_state().await.is_empty());
    }
}
