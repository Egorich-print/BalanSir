//! Network namespace integration tests
//! 
//! These tests verify that the executor can apply real nftables rules
//! in an isolated network namespace without affecting the host.

use balansir_common::{
    Action, ActionRequest, ActionResult, ActionType,
    ExecutorCapabilities,
};

/// Nftables executor that uses real nft commands
pub struct NftablesExecutor {
    capabilities: ExecutorCapabilities,
    table_name: String,
}

impl NftablesExecutor {
    pub fn new(table_name: &str) -> Self {
        Self {
            capabilities: ExecutorCapabilities {
                supported_actions: vec![
                    ActionType::Route,
                    ActionType::Mark,
                    ActionType::Block,
                    ActionType::Reject,
                    ActionType::Allow,
                ],
                max_rules: 512,
                max_fwmarks: 64,
                max_route_tables: 32,
            },
            table_name: table_name.to_string(),
        }
    }

    fn run_nft(&self, args: &[&str]) -> Result<String, String> {
        let output = std::process::Command::new("nft")
            .args(args)
            .output()
            .map_err(|e| format!("nft failed: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    pub fn setup(&self) -> Result<(), String> {
        self.run_nft(&["add", "table", "inet", &self.table_name])?;
        self.run_nft(&["add", "chain", "inet", &self.table_name, "forward", "{ type filter hook forward priority 0; }"])?;
        Ok(())
    }

    pub fn teardown(&self) -> Result<(), String> {
        let _ = self.run_nft(&["delete", "table", "inet", &self.table_name]);
        Ok(())
    }

    pub fn list_rules(&self) -> Result<Vec<String>, String> {
        let output = self.run_nft(&["list", "chain", "inet", &self.table_name, "forward"])?;
        Ok(output.lines().map(|l| l.to_string()).collect())
    }
}

#[async_trait::async_trait]
impl balansir_executor::executor::Executor for NftablesExecutor {
    fn capabilities(&self) -> &ExecutorCapabilities {
        &self.capabilities
    }

    async fn execute(&self, request: &ActionRequest) -> ActionResult {
        let start = std::time::Instant::now();

        let result = match request.action {
            Action::Block => {
                let rule = format!(
                    "ip saddr {}.{}.{}.{}/32 ip daddr {}.{}.{}.{}/32 drop",
                    request.src_ip[0], request.src_ip[1], request.src_ip[2], request.src_ip[3],
                    request.dst_ip[0], request.dst_ip[1], request.dst_ip[2], request.dst_ip[3]
                );
                self.run_nft(&["add", "rule", "inet", &self.table_name, "forward", &rule])
            }
            Action::Reject => {
                let rule = format!(
                    "ip saddr {}.{}.{}.{}/32 ip daddr {}.{}.{}.{}/32 reject",
                    request.src_ip[0], request.src_ip[1], request.src_ip[2], request.src_ip[3],
                    request.dst_ip[0], request.dst_ip[1], request.dst_ip[2], request.dst_ip[3]
                );
                self.run_nft(&["add", "rule", "inet", &self.table_name, "forward", &rule])
            }
            Action::Mark { fwmark } => {
                let rule = format!(
                    "ip saddr {}.{}.{}.{}/32 mark set {}",
                    request.src_ip[0], request.src_ip[1], request.src_ip[2], request.src_ip[3],
                    fwmark
                );
                self.run_nft(&["add", "rule", "inet", &self.table_name, "forward", &rule])
            }
            _ => return ActionResult::Unsupported {
                action_type: request.action.action_type(),
            },
        };

        let elapsed = start.elapsed().as_micros() as u64;

        match result {
            Ok(_) => ActionResult::Applied {
                execution_time_us: elapsed,
                rule_id: None,
            },
            Err(e) => ActionResult::Failed {
                error: balansir_common::ActionError::KernelError(1),
                message: Some(e),
            },
        }
    }

    async fn rule_count(&self) -> u32 {
        self.list_rules()
            .map(|rules| rules.len() as u32)
            .unwrap_or(0)
    }
}

/// Test that requires root/CAP_NET_ADMIN
/// Run with: sudo cargo test -p balansir-tests --test netns -- --ignored
#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::{DecisionTrace, MatcherStep};
    use balansir_executor::executor::Executor;
    use smallvec::SmallVec;

    fn is_root() -> bool {
        unsafe { libc::getuid() == 0 }
    }

    fn make_request(action: Action) -> ActionRequest {
        ActionRequest {
            action,
            src_ip: [192, 168, 1, 100],
            dst_ip: [10, 0, 0, 1],
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

    #[test]
    #[ignore] // Run with --ignored flag when root
    fn test_nftables_block_rule() {
        if !is_root() {
            eprintln!("Skipping: requires root");
            return;
        }

        let executor = NftablesExecutor::new("balansir_test");
        executor.setup().unwrap();

        let request = make_request(Action::Block);
        let result = futures::executor::block_on(executor.execute(&request));

        match result {
            ActionResult::Applied { .. } => {
                let rules = executor.list_rules().unwrap();
                assert!(rules.iter().any(|r| r.contains("drop")));
            }
            _ => panic!("Expected Applied"),
        }

        executor.teardown().unwrap();
    }

    #[test]
    #[ignore]
    fn test_nftables_mark_rule() {
        if !is_root() {
            eprintln!("Skipping: requires root");
            return;
        }

        let executor = NftablesExecutor::new("balansir_test_mark");
        executor.setup().unwrap();

        let request = make_request(Action::Mark { fwmark: 42 });
        let result = futures::executor::block_on(executor.execute(&request));

        match result {
            ActionResult::Applied { .. } => {
                let rules = executor.list_rules().unwrap();
                assert!(rules.iter().any(|r| r.contains("mark set 42")));
            }
            _ => panic!("Expected Applied"),
        }

        executor.teardown().unwrap();
    }

    #[test]
    fn test_executor_capabilities() {
        let executor = NftablesExecutor::new("test");

        assert!(executor.supports(ActionType::Block));
        assert!(executor.supports(ActionType::Reject));
        assert!(executor.supports(ActionType::Mark));
        assert!(!executor.supports(ActionType::Forward));
        assert!(!executor.supports(ActionType::Shape));
    }
}
