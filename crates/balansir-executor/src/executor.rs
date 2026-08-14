use async_trait::async_trait;
use balansir_common::Result;
use balansir_common::{ActionRequest, ActionResult, ActionType, ExecutorCapabilities, PathMtu};

/// Executor trait - defines how actions are applied to the kernel/drivers
#[async_trait]
pub trait Executor: Send + Sync {
    /// Get executor capabilities
    fn capabilities(&self) -> &ExecutorCapabilities;

    /// Check if action type is supported
    fn supports(&self, action_type: ActionType) -> bool {
        self.capabilities().supported_actions.contains(&action_type)
    }

    /// Execute an action (desired state -> actual state)
    async fn execute(&self, request: &ActionRequest) -> ActionResult;

    /// Undo a previously applied action
    async fn undo(&self, request: &ActionRequest) -> ActionResult {
        ActionResult::Unsupported {
            action_type: request.action.action_type(),
        }
    }

    /// Health check
    async fn health_check(&self) -> bool {
        true
    }

    /// Get current rule count
    async fn rule_count(&self) -> u32 {
        0
    }

    /// Report the ids of rules currently present in the mechanism (A2).
    ///
    /// This is a **non-authoritative inventory**: it tells the daemon what the
    /// kernel currently holds so the daemon can reconcile against its desired
    /// state. The executor does not decide what *should* be — it only reports
    /// what *is*. Default is empty for executors with no kernel state.
    async fn actual_rule_ids(&self) -> Vec<u32> {
        Vec::new()
    }

    /// Flush all rules in the executor's mechanism.
    ///
    /// Default is `Unsupported`-free success so in-memory/test executors that
    /// track no kernel state are a no-op; the privileged nftables executor
    /// overrides this to actually flush the chain.
    async fn flush(&self) -> Result<()> {
        Ok(())
    }

    /// Remove a previously applied rule by its stable rule id.
    ///
    /// The default reports failure (not implemented) so an executor that does
    /// not support per-rule removal is explicit rather than silently
    /// pretending success.
    async fn remove_rule(&self, _rule_id: u32) -> Result<()> {
        Err(balansir_common::error::Error::Unsupported(
            "remove_rule not implemented by this executor".into(),
        ))
    }

    /// Apply a per-path MTU adjustment (P7.2, ADR-026).
    ///
    /// The executor owns the applied path-MTU state; it reports it via
    /// `path_mtu_state` so the daemon can reconcile. Default reports
    /// Unsupported for mechanisms without MTU control.
    async fn set_path_mtu(&self, _path: &str, _mtu: u16) -> Result<()> {
        Err(balansir_common::error::Error::Unsupported(
            "set_path_mtu not implemented by this executor".into(),
        ))
    }

    /// Remove a per-path MTU adjustment (rollback), restoring the default.
    async fn restore_path_mtu(&self, _path: &str) -> Result<()> {
        Err(balansir_common::error::Error::Unsupported(
            "restore_path_mtu not implemented by this executor".into(),
        ))
    }

    /// The currently applied per-path MTU adjustments (non-authority).
    async fn path_mtu_state(&self) -> Vec<PathMtu> {
        Vec::new()
    }

    /// Apply a QoS shaping plan (HTB classes per interface).
    async fn apply_qos(&self, _plan: &balansir_common::QosPlan) -> Result<()> {
        Ok(())
    }

    /// Clear shaping on an interface.
    async fn clear_qos(&self, _interface: &str) -> Result<()> {
        Ok(())
    }

    /// Report interfaces currently carrying shaping (non-authority).
    async fn qos_state(&self, _interfaces: &[String]) -> balansir_common::QosState {
        balansir_common::QosState::default()
    }
}

/// Dummy executor for testing
pub struct DummyExecutor {
    capabilities: ExecutorCapabilities,
    log: std::sync::Mutex<Vec<(ActionRequest, ActionResult)>>,
    applied: std::sync::Mutex<Vec<ActionRequest>>,
}

impl Default for DummyExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl DummyExecutor {
    pub fn new() -> Self {
        Self {
            capabilities: ExecutorCapabilities {
                supported_actions: vec![
                    ActionType::Route,
                    ActionType::Mark,
                    ActionType::Block,
                    ActionType::Reject,
                    ActionType::Allow,
                    ActionType::Forward,
                    ActionType::Log,
                ],
                max_rules: 1024,
                max_fwmarks: 256,
                max_route_tables: 64,
            },
            log: std::sync::Mutex::new(Vec::new()),
            applied: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn log(&self) -> Vec<(ActionRequest, ActionResult)> {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[async_trait]
impl Executor for DummyExecutor {
    fn capabilities(&self) -> &ExecutorCapabilities {
        &self.capabilities
    }

    async fn execute(&self, request: &ActionRequest) -> ActionResult {
        let mut log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        let mut applied = self.applied.lock().unwrap_or_else(|e| e.into_inner());

        // Check for idempotency (already applied)
        let already_applied = applied.iter().any(|r| r.action == request.action);
        let result = if already_applied {
            ActionResult::AlreadyApplied
        } else {
            applied.push(request.clone());
            ActionResult::Applied {
                execution_time_us: 100,
                rule_id: Some(applied.len() as u32),
            }
        };

        log.push((request.clone(), result.clone()));
        result
    }

    async fn undo(&self, request: &ActionRequest) -> ActionResult {
        let mut applied = self.applied.lock().unwrap_or_else(|e| e.into_inner());
        applied.retain(|r| r.action != request.action);

        ActionResult::Applied {
            execution_time_us: 50,
            rule_id: None,
        }
    }

    async fn rule_count(&self) -> u32 {
        self.applied.lock().unwrap_or_else(|e| e.into_inner()).len() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::{Action, DecisionTrace, DriverId};
    use smallvec::SmallVec;

    fn make_request(action: Action) -> ActionRequest {
        ActionRequest {
            action,
            src_ip: std::net::IpAddr::from([192, 168, 1, 1]),
            dst_ip: std::net::IpAddr::from([142, 250, 80, 46]),
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            interface: 1,
            trace: DecisionTrace {
                policy_id: 1,
                steps: SmallVec::new(),
                action,
                execution_time_us: 0,
                correlation_id: 0,
            },
        }
    }

    #[tokio::test]
    async fn test_dummy_executor_basic() {
        let executor = DummyExecutor::new();

        assert!(executor.supports(ActionType::Route));
        assert!(executor.supports(ActionType::Block));
        assert!(!executor.supports(ActionType::Shape));

        let request = make_request(Action::Block);
        let result = executor.execute(&request).await;

        match result {
            ActionResult::Applied { rule_id, .. } => {
                assert_eq!(rule_id, Some(1));
            }
            _ => panic!("Expected Applied"),
        }

        assert_eq!(executor.rule_count().await, 1);
    }

    #[tokio::test]
    async fn test_dummy_executor_idempotent() {
        let executor = DummyExecutor::new();

        let request = make_request(Action::Block);

        // First apply
        let result1 = executor.execute(&request).await;
        assert!(matches!(result1, ActionResult::Applied { .. }));

        // Second apply (idempotent)
        let result2 = executor.execute(&request).await;
        assert!(matches!(result2, ActionResult::AlreadyApplied));

        // Still only one rule
        assert_eq!(executor.rule_count().await, 1);
    }

    #[tokio::test]
    async fn test_dummy_executor_driver_forward() {
        let executor = DummyExecutor::new();

        let request = make_request(Action::Forward {
            driver: DriverId::WireGuard,
        });

        let result = executor.execute(&request).await;
        assert!(matches!(result, ActionResult::Applied { .. }));
    }
}
