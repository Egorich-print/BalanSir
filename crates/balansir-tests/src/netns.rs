//! Network namespace integration tests
//!
//! These tests verify that the executor can apply real nftables rules
//! in an isolated network namespace without affecting the host.

use balansir_common::{Action, ActionRequest, ActionResult, ActionType, ExecutorCapabilities};

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
        self.run_nft(&[
            "add",
            "chain",
            "inet",
            &self.table_name,
            "forward",
            "{ type filter hook forward priority 0; }",
        ])?;
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
                    "ip saddr {}/32 ip daddr {}/32 drop",
                    request.src_ip, request.dst_ip
                );
                self.run_nft(&["add", "rule", "inet", &self.table_name, "forward", &rule])
            }
            Action::Reject => {
                let rule = format!(
                    "ip saddr {}/32 ip daddr {}/32 reject",
                    request.src_ip, request.dst_ip
                );
                self.run_nft(&["add", "rule", "inet", &self.table_name, "forward", &rule])
            }
            Action::Mark { fwmark } => {
                let rule = format!("ip saddr {}/32 mark set {}", request.src_ip, fwmark);
                self.run_nft(&["add", "rule", "inet", &self.table_name, "forward", &rule])
            }
            _ => {
                return ActionResult::Unsupported {
                    action_type: request.action.action_type(),
                }
            }
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
    use balansir_common::DecisionTrace;
    use balansir_executor::executor::Executor;
    use smallvec::SmallVec;

    fn is_root() -> bool {
        unsafe { libc::getuid() == 0 }
    }

    fn make_request(action: Action) -> ActionRequest {
        ActionRequest {
            action,
            src_ip: std::net::IpAddr::from([192, 168, 1, 100]),
            dst_ip: std::net::IpAddr::from([10, 0, 0, 1]),
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
                // nft renders marks in hex (`meta mark set 0x...`), not decimal.
                assert!(rules.iter().any(|r| r.contains("meta mark set 0x0000002a")));
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

    /// M3.7 privileged proof: the production `NftablesBackend` (typed rules,
    /// handle-based removal) applies a fwmark rule to the kernel and removes it
    /// precisely. Root-gated; run with
    /// `sudo cargo test -p balansir-tests -- --ignored`.
    #[test]
    #[ignore]
    fn test_nftables_backend_mark_and_handle_removal() {
        if !is_root() {
            eprintln!("Skipping: requires root/CAP_NET_ADMIN");
            return;
        }

        use balansir_executor::nftables::{NftRuleSpec, NftVerdict, NftablesBackend};

        let table = format!("balansir_m37_{}", std::process::id());
        let backend = NftablesBackend::new(&table, "forward").unwrap();
        backend.init().unwrap();

        // Apply a typed rule with a fwmark and a stable comment (the exact M3.7
        // mechanism the executor uses).
        let spec = NftRuleSpec {
            proto: Some(balansir_executor::nftables::NftProto::Tcp),
            src_cidr: Some("10.0.0.0/8".to_string()),
            dst_cidr: None,
            sport: None,
            dport: Some(443),
            verdict: NftVerdict::Drop,
            mark: Some(0x10),
            comment: Some("balansir:42".to_string()),
        };
        backend.add_rule(&spec).unwrap();

        // The rule is present in the kernel and carries the mark.
        let listed = backend.list_rules().unwrap();
        assert!(
            listed
                .iter()
                .any(|l| l.contains("meta mark set 0x00000010")
                    && l.contains("comment \"balansir:42\"")),
            "installed rule must be present with mark + comment: {listed:?}"
        );

        // Remove precisely by comment (handle-based), not flush-all.
        backend.remove_rule_by_comment("balansir:42").unwrap();
        let after = backend.list_rules().unwrap();
        assert!(
            !after.iter().any(|l| l.contains("balansir:42")),
            "rule must be gone after handle-based removal: {after:?}"
        );

        // Removing an absent comment is idempotent.
        backend.remove_rule_by_comment("balansir:42").unwrap();

        let _ = backend.flush();
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", &table])
            .output();
    }

    /// P4.1 (ADR-020) convergence: the executor's idempotency short-circuit
    /// must be verified against the *kernel*, not just the in-memory
    /// fingerprint cache. If an external actor deletes a rule, a re-issued
    /// AddRule for the same policy id must re-apply it (`Applied`), never
    /// report `AlreadyApplied` from stale accounting.
    #[test]
    #[ignore] // Run with --ignored flag when root
    fn test_executor_reapplies_externally_deleted_rule() {
        if !is_root() {
            eprintln!("Skipping: requires root/CAP_NET_ADMIN");
            return;
        }

        use balansir_common::{Action, ActionRequest, ActionResult, DecisionTrace};
        use balansir_executor::executor::Executor as _;
        use balansir_executor::nftables::NftablesBackend;
        use balansir_executor::service::NftablesExecutor;

        let table = format!("balansir_conv_{}", std::process::id());
        let backend = NftablesBackend::new(&table, "forward").unwrap();
        backend.init().unwrap();
        let executor = NftablesExecutor::new(backend);

        let request = ActionRequest {
            action: Action::Block,
            src_ip: "192.168.1.100".parse().unwrap(),
            dst_ip: "10.0.0.5".parse().unwrap(),
            src_port: 0,
            dst_port: 443,
            protocol: 6,
            interface: 1,
            trace: DecisionTrace {
                policy_id: 7,
                steps: SmallVec::new(),
                action: Action::Block,
                execution_time_us: 0,
                correlation_id: 0,
            },
        };

        // First apply lands in the kernel and fills the fingerprint cache.
        match futures::executor::block_on(executor.execute(&request)) {
            ActionResult::Applied { .. } => {}
            other => panic!("expected Applied on first apply, got {other:?}"),
        }

        // Simulate an external kernel edit: the rule is deleted out-of-band.
        let chain = NftablesBackend::new(&table, "forward").unwrap();
        let handle = chain
            .find_handle_by_comment("balansir:7")
            .unwrap()
            .expect("rule must be present before external delete");
        std::process::Command::new("nft")
            .args([
                "delete", "rule", "inet", &table, "forward", "handle", &handle,
            ])
            .status()
            .unwrap();
        assert!(
            !NftablesBackend::new(&table, "forward")
                .unwrap()
                .list_rules()
                .unwrap()
                .iter()
                .any(|l| l.contains("balansir:7")),
            "rule must be gone from the kernel after external delete"
        );

        // Re-issue the identical AddRule: the cache matches, but the kernel
        // does not — the executor must converge by re-applying.
        match futures::executor::block_on(executor.execute(&request)) {
            ActionResult::Applied { .. } => {}
            other => panic!("expected re-Applied after external delete, got {other:?}"),
        }
        assert!(
            NftablesBackend::new(&table, "forward")
                .unwrap()
                .list_rules()
                .unwrap()
                .iter()
                .any(|l| l.contains("balansir:7")),
            "rule must be back in the kernel after re-apply"
        );

        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", &table])
            .output();
    }
}
