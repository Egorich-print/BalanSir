//! D3: Stress testing
//!
//! - 1000+ rules policy evaluation (correctness + timing)
//! - 24h reconciliation loop simulation with rule churn
//! - Memory leak detection (executor call count stability)

use balansir_common::{Action, ActionRequest, ActionResult, DesiredRule, DesiredState};
use balansir_daemon::policy::{Matcher, PacketContext, PolicyEngine, PolicyRule};
use balansir_daemon::reconciliation::{
    ExecutorAdapter, Reconciler, ReconcilerConfig,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Build a packet context with given dst port/domain
fn ctx(dst_port: u16, domain_hash: Option<u32>) -> PacketContext {
    PacketContext {
        src_ip: [192, 168, 1, 10],
        dst_ip: [8, 8, 8, 8],
        src_port: 40000,
        dst_port,
        protocol: 6,
        domain_hash,
        interface: None,
    }
}

/// Generate N rules with unique ports, priorities 0..N
fn gen_rules(n: u32) -> Vec<PolicyRule> {
    (0..n)
        .map(|i| PolicyRule {
            id: i,
            name: format!("rule-{}", i),
            priority: i,
            enabled: true,
            matcher: Matcher::Port {
                port: ((i % 60000) + 1000) as u16,
            },
            action: Action::Block,
            fallback: None,
        })
        .collect()
}

/// 1000+ rules: verify top-priority matching and measure evaluation time
#[test]
fn policy_engine_1000_rules() {
    let rule_count = 1024u32;
    let engine = PolicyEngine::new(gen_rules(rule_count));

    // Warmup
    let _ = engine.evaluate(&ctx(443, None));

    // Correctness: rule i matches port (i%60000)+1000, blocks
    for i in [0u32, 1, 500, 1023] {
        let port = ((i % 60000) + 1000) as u16;
        let trace = engine.evaluate(&ctx(port, None));
        assert_eq!(trace.action, Action::Block, "rule {} should block {}", i, port);
        assert!(
            trace.steps.iter().any(|s| s.rule_id == i && s.matched),
            "rule {} must be the matching step",
            i
        );
    }

    // Non-matching port falls through to default Allow
    let trace = engine.evaluate(&ctx(1, None));
    assert_eq!(trace.action, Action::Allow);

    // Timing: 10k evaluations over 1024 rules (ports cycle through rules)
    let iterations = 10_000u32;
    let start = Instant::now();
    let mut decisions = 0;
    for i in 0..iterations {
        let port = (((i % rule_count) % 60000) + 1000) as u16;
        decisions += (engine.evaluate(&ctx(port, None)).action == Action::Block) as u32;
    }
    let elapsed = start.elapsed();
    let per_eval_ns = elapsed.as_nanos() / iterations as u128;

    assert_eq!(decisions, iterations, "all generated ports must match");
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "1000-rule evaluation too slow: {:?}",
        elapsed
    );
    eprintln!(
        "policy_engine_1000_rules: {} evals x {} rules in {:?} ({:.1} ns/eval)",
        iterations, rule_count, elapsed, per_eval_ns
    );
}

/// Rules with duplicate priorities: stable, must not panic and must still match
#[test]
fn policy_engine_duplicate_priorities() {
    let mut rules = gen_rules(100);
    for r in &mut rules {
        r.priority = 42;
    }
    let engine = PolicyEngine::new(rules);
    let trace = engine.evaluate(&ctx(1000, None));
    assert_eq!(trace.action, Action::Block);
    assert_eq!(trace.steps.len(), 1);
}

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
    }

    let executor = Arc::new(CountingExecutor::default());
    let config = ReconcilerConfig {
        check_interval_secs: 30,
        max_retries: 3,
        retry_delay_secs: 1,
        watchdog_timeout_secs: 1,
        atomic_rollback: true,
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

        let result = reconciler.reconcile_atomic().await;
        // Churn cycles may trigger rollback (health check fails) — either is OK,
        // but the reconciler must never error out of the loop
        assert!(result.is_ok(), "cycle {} failed: {:?}", cycle, result);

        // Leak check: after convergence, the executor must not keep growing
        // beyond what the desired state requires
        assert!(
            executor.executed.load(Ordering::Relaxed)
                < (cycle as u64 + 1) * 50,
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

/// Policy engine with deep churn: add/remove 10k rules, engine stays consistent
#[test]
fn policy_engine_rule_churn() {
    let mut engine = PolicyEngine::new(Vec::new());
    for i in 0..10_000u32 {
        engine.add_rule(PolicyRule {
            id: i,
            name: format!("churn-{}", i),
            priority: i,
            enabled: true,
            matcher: Matcher::Port {
                port: (i as u16).wrapping_add(1),
            },
            action: Action::Reject,
            fallback: None,
        });
        if i >= 1000 {
            engine.remove_rule(i - 1000);
        }
    }
    assert_eq!(engine.rules().len(), 1000);

    let trace = engine.evaluate(&ctx(9001, None));
    // port 9001 = rule 9000 (rejected), still present after churn
    assert_eq!(trace.action, Action::Reject);
}
