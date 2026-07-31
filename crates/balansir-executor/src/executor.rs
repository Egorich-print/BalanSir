use async_trait::async_trait;
use balansir_common::{
    ActionRequest, ActionResult, ActionType, ExecutorCapabilities,
};

/// Executor trait - defines how actions are applied to the kernel/drivers
#[async_trait]
pub trait Executor: Send + Sync {
    /// Get executor capabilities
    fn capabilities(&self) -> &ExecutorCapabilities;

    /// Check if action type is supported
    fn supports(&self, action_type: ActionType) -> bool {
        self.capabilities()
            .supported_actions
            .contains(&action_type)
    }

    /// Execute an action
    async fn execute(&self, request: &ActionRequest) -> ActionResult;

    /// Undo a previously applied action (if possible)
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
}

/// Dummy executor for testing
pub struct DummyExecutor {
    capabilities: ExecutorCapabilities,
    log: std::sync::Mutex<Vec<ActionRequest>>,
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
                    ActionType::Log,
                ],
                max_rules: 1024,
                max_fwmarks: 256,
                max_route_tables: 64,
            },
            log: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn log(&self) -> Vec<ActionRequest> {
        self.log.lock().unwrap().clone()
    }
}

#[async_trait]
impl Executor for DummyExecutor {
    fn capabilities(&self) -> &ExecutorCapabilities {
        &self.capabilities
    }

    async fn execute(&self, request: &ActionRequest) -> ActionResult {
        let mut log = self.log.lock().unwrap();
        log.push(request.clone());

        ActionResult::Success {
            execution_time_us: 100,
            rule_id: Some(log.len() as u32),
        }
    }

    async fn undo(&self, request: &ActionRequest) -> ActionResult {
        ActionResult::Success {
            execution_time_us: 50,
            rule_id: None,
        }
    }

    async fn rule_count(&self) -> u32 {
        self.log.lock().unwrap().len() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::{Action, DecisionTrace, MatcherStep};
    use smallvec::SmallVec;

    #[tokio::test]
    async fn test_dummy_executor() {
        let executor = DummyExecutor::new();

        assert!(executor.supports(ActionType::Route));
        assert!(executor.supports(ActionType::Block));
        assert!(!executor.supports(ActionType::Forward));

        let request = ActionRequest {
            action: Action::Block,
            src_ip: [192, 168, 1, 1],
            dst_ip: [142, 250, 80, 46],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            interface: 1,
            trace: DecisionTrace {
                policy_id: 1,
                steps: SmallVec::new(),
                action: Action::Block,
                execution_time_us: 0,
                correlation_id: 0,
            },
        };

        let result = executor.execute(&request).await;
        match result {
            ActionResult::Success { rule_id, .. } => {
                assert_eq!(rule_id, Some(1));
            }
            _ => panic!("Expected success"),
        }

        assert_eq!(executor.rule_count().await, 1);
        assert_eq!(executor.log().len(), 1);
    }
}
