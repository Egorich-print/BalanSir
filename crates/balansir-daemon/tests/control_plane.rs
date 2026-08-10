//! M3.4.1 production control-plane smoke test.
//!
//! Proves the daemon's real reconcile path — the same assembly `main.rs`
//! constructs — actually drives the control-plane FSM: desired -> Coordinator
//! -> BasicPlanner -> plan -> execution adapter -> commit/rollback. The
//! mechanism is pending (M3.6), so execution must honestly report Unsupported
//! and the transaction must roll back, leaving ActualState untouched.

use balansir_common::{Action, DesiredRule, DesiredState};
use balansir_daemon::reconciliation::{PendingMechanismAdapter, Reconciler, ReconcilerConfig};
use std::sync::Arc;

/// A rule-bearing desired state forces a non-empty plan and a real execution
/// attempt. With the mechanism pending, that attempt must be `Unsupported`,
/// which fails the report and flows through the coordinator's rollback path.
#[tokio::test]
async fn production_reconcile_with_pending_mechanism_rolls_back() {
    let desired = DesiredState {
        rules: vec![DesiredRule {
            id: 1,
            action: Action::Block,
            priority: 100,
        }],
        drivers: Vec::new(),
    };

    let reconciler = Reconciler::new(
        desired,
        Arc::new(PendingMechanismAdapter),
        ReconcilerConfig::default(),
    );

    // The FSM runs, execution is attempted, and the transaction fails
    // (mechanism pending) rather than claiming success.
    let err = reconciler
        .reconcile()
        .await
        .expect_err("reconcile must fail when the mechanism is pending (Unsupported), not succeed");
    assert!(
        err.to_string().contains("execution failed"),
        "expected an execution failure from the coordinator, got: {err}"
    );

    // No fictitious applied rule: ActualState stays empty.
    let actual = reconciler.get_actual().await;
    assert!(
        actual.active_rules.is_empty(),
        "ActualState must not contain a rule the pending mechanism never applied"
    );

    // No commit: generation is not bumped.
    assert_eq!(reconciler.generation(), 1);
}
