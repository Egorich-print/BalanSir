//! Privileged executor command loop (M3.6).
//!
//! The executor is the privileged operation boundary. It connects to the
//! daemon (the IPC server) and then processes a narrowly defined allowlisted
//! command set pushed by the daemon over the authenticated Unix socket.
//!
//! Security invariants:
//! - peer UID is authenticated at connection time (`SO_PEERCRED`/getpeereid);
//! - only the allowlisted `MsgType`s are dispatched — anything else is an
//!   explicit error;
//! - no shell, no arbitrary command execution; each op maps to a typed
//!   mechanism call.

use async_trait::async_trait;
use balansir_common::ipc::{IpcClientConnection, IpcMessage, MsgType};
use balansir_common::{ActionRequest, ActionResult, Result};

use crate::executor::Executor;

/// A concrete privileged mechanism: nftables-backed rule execution.
///
/// Maps `ActionRequest` -> `NftRuleSpec` for the supported verdicts and
/// executes them against the `NftablesBackend`. Rules that have no nft
/// representation (e.g. `Forward`) are honestly reported as `Unsupported`
/// rather than fabricated.
#[derive(Debug)]
pub struct NftablesExecutor {
    backend: crate::nftables::NftablesBackend,
}

impl NftablesExecutor {
    pub fn new(backend: crate::nftables::NftablesBackend) -> Self {
        Self { backend }
    }
}

fn to_nft_verdict(action: &balansir_common::Action) -> Option<crate::nftables::NftVerdict> {
    use crate::nftables::NftVerdict;
    match action {
        balansir_common::Action::Allow => Some(NftVerdict::Accept),
        balansir_common::Action::Block => Some(NftVerdict::Drop),
        _ => None,
    }
}

fn to_nft_spec(request: &ActionRequest) -> Option<crate::nftables::NftRuleSpec> {
    use crate::nftables::NftRuleSpec;
    let verdict = to_nft_verdict(&request.action)?;
    let proto = match request.protocol {
        6 => Some(crate::nftables::NftProto::Tcp),
        17 => Some(crate::nftables::NftProto::Udp),
        _ => None,
    };
    let src_cidr = if request.src_ip == [0; 4] {
        None
    } else {
        Some(format!(
            "{}.{}.{}.{}/32",
            request.src_ip[0], request.src_ip[1], request.src_ip[2], request.src_ip[3]
        ))
    };
    Some(NftRuleSpec {
        proto,
        src_cidr,
        dport: if request.dst_port != 0 {
            Some(request.dst_port)
        } else {
            None
        },
        verdict,
    })
}

#[async_trait]
impl Executor for NftablesExecutor {
    fn capabilities(&self) -> &balansir_common::ExecutorCapabilities {
        static CAPS: std::sync::OnceLock<balansir_common::ExecutorCapabilities> =
            std::sync::OnceLock::new();
        CAPS.get_or_init(|| balansir_common::ExecutorCapabilities {
            supported_actions: vec![
                balansir_common::ActionType::Block,
                balansir_common::ActionType::Allow,
            ],
            max_rules: 1024,
            max_fwmarks: 0,
            max_route_tables: 0,
        })
    }

    async fn execute(&self, request: &ActionRequest) -> ActionResult {
        let Some(spec) = to_nft_spec(request) else {
            return ActionResult::Unsupported {
                action_type: request.action.action_type(),
            };
        };
        match self.backend.add_rule(&spec) {
            Ok(()) => ActionResult::Applied {
                execution_time_us: 0,
                rule_id: None,
            },
            Err(e) => ActionResult::Failed {
                error: balansir_common::ActionError::KernelError(0),
                message: Some(e.to_string()),
            },
        }
    }

    async fn flush(&self) -> Result<()> {
        self.backend.flush()
    }

    async fn rule_count(&self) -> u32 {
        0
    }
}

/// Allowed executor operations. Anything not in this set is rejected before
/// reaching any mechanism.
fn is_allowlisted(msg_type: MsgType) -> bool {
    matches!(
        msg_type,
        MsgType::AddRule | MsgType::RemoveRule | MsgType::FlushRules | MsgType::HealthCheck
    )
}

/// Serve a single authenticated executor connection until EOF.
///
/// Each message is validated against the allowlist, dispatched to the
/// mechanism, and answered with an explicit response. The daemon pushes
/// privileged operations; the executor never initiates them.
pub async fn serve_connection(
    conn: &mut IpcClientConnection,
    executor: &dyn Executor,
) -> Result<()> {
    loop {
        let msg = conn.recv().await?;
        let response = dispatch(&msg, executor).await;
        conn.send(&response).await?;
    }
}

/// Dispatch one allowlisted command to the mechanism and build a response.
///
/// Used both by the server loop and by tests.
pub async fn dispatch(msg: &IpcMessage, executor: &dyn Executor) -> IpcMessage {
    if !is_allowlisted(msg.msg_type) {
        tracing::warn!(?msg.msg_type, "executor rejected non-allowlisted operation");
        return IpcMessage::response_error(msg.correlation_id, "operation not allowed");
    }

    match msg.msg_type {
        MsgType::HealthCheck => IpcMessage::response_ok(msg.correlation_id),
        MsgType::AddRule => {
            let Ok(request) = postcard::from_bytes::<ActionRequest>(&msg.payload) else {
                return IpcMessage::response_error(msg.correlation_id, "invalid AddRule payload");
            };
            let result = executor.execute(&request).await;
            // Encode the typed result back to the daemon.
            let payload = match postcard::to_allocvec(&result) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return IpcMessage::response_error(
                        msg.correlation_id,
                        "failed to encode result",
                    )
                }
            };
            IpcMessage::response_data(msg.correlation_id, payload)
        }
        MsgType::FlushRules => match executor.flush().await {
            Ok(()) => IpcMessage::response_ok(msg.correlation_id),
            Err(e) => IpcMessage::response_error(msg.correlation_id, &e.to_string()),
        },
        MsgType::RemoveRule => {
            // Per-rule removal needs a handle-tracking mechanism that is not yet
            // represented; the operation is allowlisted but honestly reports
            // unsupported rather than fabricating success.
            IpcMessage::response_error(
                msg.correlation_id,
                "RemoveRule mechanism not yet implemented",
            )
        }
        _ => IpcMessage::response_error(msg.correlation_id, "operation not allowed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::ipc::IpcMessage;

    fn dummy_executor() -> impl Executor {
        crate::executor::DummyExecutor::new()
    }

    fn message(msg_type: MsgType, payload: Vec<u8>) -> IpcMessage {
        IpcMessage::new(msg_type, 1, payload)
    }

    #[tokio::test]
    async fn rejects_non_allowlisted_operation() {
        let response = dispatch(&message(MsgType::StartDriver, vec![]), &dummy_executor()).await;
        assert_eq!(response.msg_type, MsgType::ResponseError);
    }

    #[tokio::test]
    async fn health_check_is_allowlisted() {
        let response = dispatch(&message(MsgType::HealthCheck, vec![]), &dummy_executor()).await;
        assert_eq!(response.msg_type, MsgType::ResponseOk);
    }

    #[tokio::test]
    async fn add_rule_with_invalid_payload_is_rejected() {
        let response = dispatch(&message(MsgType::AddRule, vec![1, 2, 3]), &dummy_executor()).await;
        assert_eq!(response.msg_type, MsgType::ResponseError);
    }

    #[tokio::test]
    async fn add_rule_with_valid_payload_returns_typed_result() {
        let request = ActionRequest {
            action: balansir_common::Action::Block,
            src_ip: [0; 4],
            dst_ip: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            interface: 0,
            trace: balansir_common::DecisionTrace {
                policy_id: 1,
                steps: smallvec::SmallVec::new(),
                action: balansir_common::Action::Block,
                execution_time_us: 0,
                correlation_id: 0,
            },
        };
        let payload = postcard::to_allocvec(&request).unwrap();
        let response = dispatch(&message(MsgType::AddRule, payload), &dummy_executor()).await;
        assert_eq!(response.msg_type, MsgType::ResponseData);
        let result: ActionResult = postcard::from_bytes(&response.payload).unwrap();
        assert!(matches!(result, ActionResult::Applied { .. }));
    }

    #[tokio::test]
    async fn remove_rule_is_allowlisted_but_honestly_unsupported() {
        let response = dispatch(&message(MsgType::RemoveRule, vec![]), &dummy_executor()).await;
        assert_eq!(response.msg_type, MsgType::ResponseError);
        let err = String::from_utf8(response.payload.clone()).unwrap();
        assert!(err.contains("not yet implemented"));
    }

    #[tokio::test]
    async fn flush_rules_dispatches() {
        // DummyExecutor's flush is a no-op success; the point is the op is
        // allowlisted and dispatched (not rejected).
        let response = dispatch(&message(MsgType::FlushRules, vec![]), &dummy_executor()).await;
        assert_eq!(response.msg_type, MsgType::ResponseOk);
    }

    #[test]
    fn nft_spec_maps_supported_actions() {
        use crate::nftables::NftVerdict;

        let block = ActionRequest {
            action: balansir_common::Action::Block,
            src_ip: [10, 0, 0, 1],
            dst_ip: [0; 4],
            src_port: 0,
            dst_port: 443,
            protocol: 6,
            interface: 0,
            trace: balansir_common::DecisionTrace {
                policy_id: 1,
                steps: smallvec::SmallVec::new(),
                action: balansir_common::Action::Block,
                execution_time_us: 0,
                correlation_id: 0,
            },
        };
        let spec = to_nft_spec(&block).expect("Block must map to a spec");
        assert!(matches!(spec.verdict, NftVerdict::Drop));
        assert_eq!(spec.dport, Some(443));
        assert_eq!(spec.src_cidr.as_deref(), Some("10.0.0.1/32"));

        let allow = ActionRequest {
            action: balansir_common::Action::Allow,
            src_ip: [0; 4],
            dst_ip: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            interface: 0,
            trace: balansir_common::DecisionTrace {
                policy_id: 2,
                steps: smallvec::SmallVec::new(),
                action: balansir_common::Action::Allow,
                execution_time_us: 0,
                correlation_id: 0,
            },
        };
        let spec = to_nft_spec(&allow).expect("Allow must map to a spec");
        assert!(matches!(spec.verdict, NftVerdict::Accept));
        assert!(spec.src_cidr.is_none());

        // Forward has no nft verdict -> honest Unsupported at execute time.
        let forward = ActionRequest {
            action: balansir_common::Action::Forward {
                driver: balansir_common::DriverId::WireGuard,
            },
            src_ip: [0; 4],
            dst_ip: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            interface: 0,
            trace: balansir_common::DecisionTrace {
                policy_id: 3,
                steps: smallvec::SmallVec::new(),
                action: balansir_common::Action::Forward {
                    driver: balansir_common::DriverId::WireGuard,
                },
                execution_time_us: 0,
                correlation_id: 0,
            },
        };
        assert!(to_nft_spec(&forward).is_none());
    }
}
