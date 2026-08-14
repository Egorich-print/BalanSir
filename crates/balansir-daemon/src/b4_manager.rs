//! B4 component manager: owns the B4 controller loop and publishes its state
//! into the unified subsystem snapshot + event bus.
//!
//! This makes B4 a first-class BalanSir component with the same ownership
//! pattern as QoS / interfaces / Tailscale:
//!
//! ```text
//! B4Engine (pure decision) → B4Controller → executor boundary
//!      ↓ observations (shared DNS registry + host stack)
//! B4Manager loop → SharedSubsystemSnapshot + SubsystemEvent → REST/SSE/WebUI
//! ```
//!
//! The controller's `PathMtuReconciler` runs in the same loop so the executor's
//! reported per-path MTU is converged to the daemon's intent (P4.1 ownership).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{broadcast, RwLock};
use tracing::{info, warn};

use balansir_common::path_health::{PathHealth, PathHealthConfig, PathSample};
use balansir_common::subsystems::{
    B4FlowView, B4Snapshot, SharedSubsystemSnapshot, SubsystemEvent,
};

use crate::b4_engine::config::B4Toml;
use crate::b4_engine::controller::{B4Controller, PathMtuReconciler};
use crate::b4_engine::host::CompositeObserver;
use crate::b4_engine::observe::B4Observation;
use crate::b4_engine::policy::B4Policy;
use crate::b4_engine::state::B4Event;
use crate::reconciliation::{DnsRegistry, ExecutorAdapter};

/// B4 controller handle used by the API control seam: the loop owns the
/// mutable controller; the handle only toggles the pause flag (which the loop
/// polls) — no concurrent access to the stateful engine.
#[derive(Clone)]
pub struct B4ManagerHandle {
    paused: Arc<AtomicBool>,
}

impl B4ManagerHandle {
    pub async fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
    }
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }
}

/// B4 component manager. `spawn` starts the runtime loop; state flows into
/// `SharedSubsystemSnapshot` and events into the shared broadcast channel.
pub struct B4Manager {
    controller: B4Controller,
    policy: B4Policy,
    snapshot: SharedSubsystemSnapshot,
    events: broadcast::Sender<SubsystemEvent>,
    config_path: Option<String>,
    enabled: bool,
    paused: Arc<AtomicBool>,
    last_error: Arc<RwLock<Option<String>>>,
    /// Unified path-health trackers per flow (mission §9), fed from the same
    /// host-stack observations the engine classifies on.
    paths: Mutex<HashMap<String, PathHealth>>,
}

/// B4 path-health thresholds are aligned with the engine's existing
/// classification (RTT ≥ 400 ms degrades) so both views agree.
fn b4_path_config() -> PathHealthConfig {
    PathHealthConfig {
        latency_threshold_ms: 400.0,
        enter_degraded: 2,
        exit_degraded: 3,
        cooldown: std::time::Duration::from_secs(10),
        ..PathHealthConfig::default()
    }
}

/// Map a host-stack observation to the unified path-health vocabulary without
/// inventing numbers: connectivity comes from resets/DNS, latency from RTT,
/// and retransmit/throughput collapse becomes qualitative degraded evidence.
fn sample_for(obs: &B4Observation) -> PathSample {
    let reachable = !(obs.reset_or_timeout == Some(true) || obs.dns_ok == Some(false));
    let degraded_evidence = obs.retransmissions.is_some_and(|r| r >= 3)
        || obs.throughput_bps.is_some_and(|b| b < 1_000);
    PathSample {
        latency_ms: obs.rtt.map(|d| d.as_secs_f64() * 1000.0),
        loss_pct: None,
        reachable,
        degraded_evidence,
    }
}

impl B4Manager {
    /// Build the manager from an already-validated B4 config file. Returns
    /// `Err` with a human-readable reason when the policy is rejected.
    pub fn from_toml(
        config_path: &str,
        b4_cfg: &B4Toml,
        dns_registry: Arc<DnsRegistry>,
        executor: Arc<dyn ExecutorAdapter>,
        snapshot: SharedSubsystemSnapshot,
        events: broadcast::Sender<SubsystemEvent>,
    ) -> Result<Self, String> {
        let policy: B4Policy = b4_cfg.policy()?;
        let engine_cfg = b4_cfg.engine_config();
        let observer: Arc<dyn crate::b4_engine::B4Observer> =
            Arc::new(CompositeObserver::new(Some(dns_registry)));
        let controller = B4Controller::new(policy.clone(), observer, engine_cfg, executor);
        Ok(Self {
            controller,
            policy,
            snapshot,
            events,
            config_path: Some(config_path.to_string()),
            enabled: engine_cfg.enabled,
            paused: Arc::new(AtomicBool::new(false)),
            last_error: Arc::new(RwLock::new(None)),
            paths: Mutex::new(HashMap::new()),
        })
    }

    pub fn handle(&self) -> B4ManagerHandle {
        B4ManagerHandle {
            paused: Arc::clone(&self.paused),
        }
    }

    fn profile_label(&self, flow: &str) -> String {
        let profile = self.policy.profile_for(flow);
        let caps: Vec<String> = profile
            .capabilities
            .iter()
            .map(|c| format!("{c:?}"))
            .collect();
        let mut label = caps.join(",");
        if label.is_empty() {
            label = "direct".to_string();
        }
        if profile.allow_tunnel {
            label.push_str("+tunnel");
        }
        label
    }

    /// Build a B4Snapshot from current controller + executor state.
    async fn observe_snapshot(&self) -> B4Snapshot {
        let intended = self.controller.intended_path_mtu();
        let reported = self.controller.reported_path_mtu().await;
        let mut flows: Vec<B4FlowView> = Vec::new();
        let mut keys: Vec<String> = self.controller.flow_keys();
        for domain in self.controller.policy_domains() {
            if !keys.contains(&domain) {
                keys.push(domain);
            }
        }
        for flow in keys {
            let mtu = intended
                .iter()
                .find(|p| p.path == flow)
                .map(|p| p.mtu);
            let decision = self.controller.flow_decision(&flow);
            let observation = self.controller.flow_observation(&flow);
            let health = match observation {
                Some(obs) => format!("{:?}", crate::b4_engine::classify::classify(&obs)),
                None => "Unknown".to_string(),
            };
            let path = self
                .paths
                .lock()
                .ok()
                .and_then(|guard| guard.get(&flow).map(|p| p.view()))
                .unwrap_or_default();
            flows.push(B4FlowView {
                flow: flow.clone(),
                state: format!("{:?}", self.controller.flow_state(&flow)),
                profile: self.profile_label(&flow),
                last_decision: decision.map(|d| format!("{d:?}")),
                mtu,
                health,
                rtt_ms: observation.and_then(|o| o.rtt).map(|d| d.as_millis() as u64),
                rtt_var_ms: observation.and_then(|o| o.rtt_var).map(|d| d.as_millis() as u64),
                connect_latency_ms: observation
                    .and_then(|o| o.connect_latency)
                    .map(|d| d.as_millis() as u64),
                retransmissions: observation.and_then(|o| o.retransmissions),
                throughput_bps: observation.and_then(|o| o.throughput_bps),
                dns_ok: observation.and_then(|o| o.dns_ok),
                reset_or_timeout: observation.and_then(|o| o.reset_or_timeout),
                path,
            });
        }
        flows.sort_by(|a, b| a.flow.cmp(&b.flow));
        let drift = drift_between(&intended, &reported);
        B4Snapshot {
            enabled: self.enabled,
            mtu_enabled: self.controller.mtu_enabled,
            config_path: self.config_path.clone(),
            flows,
            intended_mtu: intended,
            reported_mtu: reported,
            drift,
            last_error: self.last_error.read().await.clone(),
            paused: self.paused.load(Ordering::Relaxed),
        }
    }

    /// One full loop iteration: run each flow, reconcile MTU ownership,
    /// publish the snapshot, and emit events.
    async fn cycle(&mut self) {
        let mut keys: Vec<String> = self.controller.policy_domains();
        for f in self.controller.flow_keys() {
            if !keys.contains(&f) {
                keys.push(f);
            }
        }
        let paused = self.paused.load(Ordering::Relaxed);
        for flow in keys {
            if paused {
                continue;
            }
            let events = self.controller.run_for(&flow).await;
            self.publish_engine_events(&flow, events);
            // Feed the unified path-health tracker from the same observation
            // the engine just classified on.
            if let Some(obs) = self.controller.flow_observation(&flow) {
                if let Ok(mut guard) = self.paths.lock() {
                    let tracker = guard
                        .entry(flow.clone())
                        .or_insert_with(|| PathHealth::new(b4_path_config()));
                    tracker.observe(sample_for(&obs));
                }
            }
        }
        if !paused {
            // Ownership: converge the executor's reported MTU state to the
            // controller's intent (P4.1 — B4 never changes unknown state).
            let intended = self.controller.intended_path_mtu();
            let executor = self.controller.executor_adapter();
            let drift = PathMtuReconciler::reconcile(executor.as_ref(), &intended).await;
            if !drift.is_empty() {
                let detail = format!(
                    "B4 MTU ownership drift: {} path(s) differ from intent",
                    drift.len()
                );
                warn!("{detail}");
                *self.last_error.write().await = Some(detail.clone());
                let _ = self.events.send(SubsystemEvent::B4Drift { detail });
            }
        }
        let snapshot = self.observe_snapshot().await;
        self.snapshot
            .update(move |s| {
                s.b4 = snapshot.clone();
            })
            .await;
    }

    fn publish_engine_events(&self, flow: &str, events: Vec<B4Event>) {
        for event in events {
            let subsystem_event = match event {
                B4Event::Classified { .. } => continue, // too noisy for SSE
                B4Event::Adapted { capability, .. } => SubsystemEvent::B4Adapted {
                    flow: flow.to_string(),
                    capability: format!("{capability:?}"),
                },
                B4Event::Recovered { .. } => SubsystemEvent::B4Recovered {
                    flow: flow.to_string(),
                },
                B4Event::StrictFailed { .. } => SubsystemEvent::B4StateChanged {
                    flow: flow.to_string(),
                    state: "StrictFail".to_string(),
                },
            };
            let _ = self.events.send(subsystem_event);
        }
    }

    /// Run the B4 component loop forever (daemon task).
    pub async fn run_loop(mut self, interval_secs: u64) -> ! {
        if self.enabled {
            info!(
                "B4 engine running (interval {}s, config {:?})",
                interval_secs, self.config_path
            );
        } else {
            info!("B4 engine present but disabled by config (no adaptation)");
        }
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            // Publish a snapshot even while paused so the WebUI reflects the
            // pause state immediately.
            let snapshot = self.observe_snapshot().await;
            self.snapshot
                .update(move |s| {
                    s.b4 = snapshot.clone();
                })
                .await;
            if !self.paused.load(Ordering::Relaxed) {
                self.cycle().await;
            }
        }
    }
}

/// Compare intended vs reported per-path MTU (order-independent).
fn drift_between(intended: &[balansir_common::PathMtu], reported: &[balansir_common::PathMtu]) -> bool {
    use std::collections::HashMap;
    let want: HashMap<&str, u16> = intended
        .iter()
        .map(|p| (p.path.as_str(), p.mtu))
        .collect();
    let have: HashMap<&str, u16> = reported
        .iter()
        .map(|p| (p.path.as_str(), p.mtu))
        .collect();
    want != have
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::PathMtu;

    #[test]
    fn drift_detection() {
        let empty: Vec<PathMtu> = vec![];
        assert!(!drift_between(&empty, &empty));
        let i = vec![PathMtu {
            path: "a.example".into(),
            mtu: 1400,
        }];
        assert!(drift_between(&i, &empty));
        let r = vec![PathMtu {
            path: "a.example".into(),
            mtu: 1400,
        }];
        assert!(!drift_between(&i, &r));
    }

    #[tokio::test]
    async fn paused_handle_toggles() {
        let handle = B4ManagerHandle {
            paused: Arc::new(AtomicBool::new(false)),
        };
        assert!(!handle.is_paused());
        handle.set_paused(true).await;
        assert!(handle.is_paused());
    }

    #[test]
    fn observation_maps_to_unified_path_sample() {
        // A reset marks the path unreachable.
        let s = sample_for(&B4Observation {
            reset_or_timeout: Some(true),
            ..B4Observation::default()
        });
        assert!(!s.reachable);
        // Heavy retransmits with a normal RTT become degraded evidence
        // without inventing latency/loss numbers.
        let s = sample_for(&B4Observation {
            rtt: Some(std::time::Duration::from_millis(120)),
            retransmissions: Some(4),
            ..B4Observation::default()
        });
        assert!(s.reachable);
        assert!(s.degraded_evidence);
        assert_eq!(s.latency_ms, Some(120.0));
        // DNS failure marks the path unreachable too.
        let s = sample_for(&B4Observation {
            dns_ok: Some(false),
            ..B4Observation::default()
        });
        assert!(!s.reachable);
    }

    #[test]
    fn path_tracker_degrades_on_sustained_rtt() {
        let mut t = PathHealth::new(b4_path_config());
        let obs = || B4Observation {
            rtt: Some(std::time::Duration::from_millis(600)),
            ..B4Observation::default()
        };
        t.observe(sample_for(&obs()));
        t.observe(sample_for(&obs()));
        let view = t.view();
        assert_eq!(view.state, "degraded");
        assert!(
            view.reasons.iter().any(|r| r.contains("RTT") && r.contains("threshold")),
            "reasons: {view:?}"
        );
    }
}
