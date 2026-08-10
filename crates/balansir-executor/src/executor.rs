use async_trait::async_trait;
use balansir_common::Result;
use balansir_common::{ActionRequest, ActionResult, ActionType, ExecutorCapabilities};

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

    /// Flush all rules in the executor's mechanism.
    ///
    /// Default is `Unsupported`-free success so in-memory/test executors that
    /// track no kernel state are a no-op; the privileged nftables executor
    /// overrides this to actually flush the chain.
    async fn flush(&self) -> Result<()> {
        Ok(())
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
            src_ip: [192, 168, 1, 1],
            dst_ip: [142, 250, 80, 46],
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
