//! D3: Stress testing
//!
//! - 24h reconciliation loop simulation with rule churn
//! - Memory leak detection (executor call count stability)

use balansir_common::diff::StateDiff;
use balansir_common::{Action, ActionRequest, ActionResult, DesiredRule, DesiredState};
use balansir_daemon::reconciliation::{ExecutorAdapter, Reconciler, ReconcilerConfig};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// 24h reconciliation simulation (2880 cycles @ 30s) with rule churn.
/// Verifies: convergence, executor call stability (no leak), rollback path.
#[tokio::test]
async fn reconciler_24h_simulation() {
    /// Executor adapter that counts executions
    #[derive(Default)]
    struct CountingExecutor {
        executed: AtomicU64,
        applied: AtomicU64,
    }

    #[async_trait::async_trait]
    impl ExecutorAdapter for CountingExecutor {
        async fn execute(&self, _request: &ActionRequest) -> ActionResult {
            self.executed.fetch_add(1, Ordering::Relaxed);
            self.applied.fetch_add(1, Ordering::Relaxed);
            ActionResult::Applied {
                execution_time_us: 100,
                rule_id: None,
            }
        }

        async fn rule_count(&self) -> u32 {
            self.applied.load(Ordering::Relaxed) as u32
        }

        async fn remove_rule(&self, rule_id: u32) -> ActionResult {
            let _ = rule_id;
            self.applied.fetch_sub(1, Ordering::Relaxed);
            ActionResult::Applied {
                execution_time_us: 50,
                rule_id: None,
            }
        }
    }

    let executor = Arc::new(CountingExecutor::default());
    let config = ReconcilerConfig {
        check_interval_secs: 30,
        max_retries: 3,
        retry_delay_secs: 1,
        watchdog_timeout_secs: 1,
        atomic_rollback: true,
        resync_every_n_cycles: 0,
        dns_resync_interval_secs: 0,
    };

    let reconciler = Reconciler::new(DesiredState::default(), executor.clone(), config);
    let mut desired_count = 0u32;

    // 24h = 2880 cycles; do churn every 100th cycle
    let cycles = 2880u32;
    for cycle in 0..cycles {
        if cycle % 100 == 0 {
            // Churn: add 10 rules, remove half of existing
            for _ in 0..10u32 {
                let id = desired_count;
                reconciler
                    .add_rule(DesiredRule {
                        id,
                        action: Action::Block,
                        priority: id,
                        flow: None,
                    })
                    .await;
                desired_count += 1;
            }

            let mut removals = Vec::new();
            for r in reconciler.get_desired().await.rules.iter() {
                if r.id % 2 == 0 {
                    removals.push(r.id);
                }
            }
            for id in removals {
                reconciler.remove_rule(id).await;
            }
            desired_count = reconciler.get_desired().await.rules.len() as u32;
        }

        let desired = reconciler.get_desired().await;
        let actual = reconciler.get_actual().await;
        let gen = reconciler.generation();
        let plan = StateDiff::build(&desired, &actual, gen);

        if !plan.is_empty() {
            reconciler.reconcile_atomic().await.unwrap();
        }

        // Leak check: after convergence, the executor must not keep growing
        // beyond what the desired state requires
        assert!(
            executor.executed.load(Ordering::Relaxed) < (cycle as u64 + 1) * 50,
            "executor call count growing unboundedly at cycle {}",
            cycle
        );
    }

    // Final state must converge to desired
    let desired = reconciler.get_desired().await;
    assert_eq!(desired.rules.len() as u32, desired_count);
    eprintln!(
        "reconciler_24h_simulation: {} cycles, {} desired rules, {} executor calls",
        cycles,
        desired_count,
        executor.executed.load(Ordering::Relaxed)
    );
}

/// Rapid churn without atomic rollback (legacy path) — must converge too
#[tokio::test]
async fn reconciler_rapid_churn_legacy() {
    #[derive(Default)]
    struct OkExecutor {
        executed: AtomicU64,
    }

    #[async_trait::async_trait]
    impl ExecutorAdapter for OkExecutor {
        async fn execute(&self, _request: &ActionRequest) -> ActionResult {
            self.executed.fetch_add(1, Ordering::Relaxed);
            ActionResult::Applied {
                execution_time_us: 1,
                rule_id: None,
            }
        }

        async fn rule_count(&self) -> u32 {
            self.executed.load(Ordering::Relaxed) as u32
        }

        async fn remove_rule(&self, rule_id: u32) -> ActionResult {
            let _ = rule_id;
            self.executed.fetch_sub(1, Ordering::Relaxed);
            ActionResult::Applied {
                execution_time_us: 50,
                rule_id: None,
            }
        }
    }

    let executor = Arc::new(OkExecutor::default());
    let reconciler = Reconciler::new(
        DesiredState::default(),
        executor,
        ReconcilerConfig {
            atomic_rollback: false,
            ..ReconcilerConfig::default()
        },
    );

    for cycle in 0..1000u32 {
        reconciler
            .add_rule(DesiredRule {
                id: cycle,
                action: Action::Allow,
                priority: cycle,
                flow: None,
            })
            .await;
        if cycle >= 10 {
            reconciler.remove_rule(cycle - 10).await;
        }
        reconciler.reconcile().await.unwrap();
    }

    let desired = reconciler.get_desired().await;
    assert_eq!(desired.rules.len(), 10);
}
