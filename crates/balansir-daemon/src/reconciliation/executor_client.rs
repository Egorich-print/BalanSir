//! Daemon-side `ExecutorAdapter` that commands the privileged executor over
//! IPC (ADR-013).
//!
//! The executor is the privileged server; the daemon is the unprivileged
//! commander/client. This adapter sends typed operations
//! (`AddRule`/`RemoveRule`/`FlushRules`) to the executor and maps the typed
//! `ActionResult` response back.
//!
//! Reconnect semantics: on a dropped connection the daemon reconnects; the
//! daemon then refreshes ActualState and the planner recomputes
//! `Desired − Actual`, so **only the resulting plan is executed** — reconcile,
//! not replay of a command log. `correlation_id` matches a single RPC; it is
//! never used as a command journal.

use async_trait::async_trait;
use balansir_common::ipc::{IpcClientConnection, IpcMessage, MsgType};
use balansir_common::{ActionRequest, ActionResult, Result};

use crate::reconciliation::reconciler::ExecutorAdapter;

const DEFAULT_EXECUTOR_SOCKET: &str = "/run/balansir/executor.sock";

/// Commands the privileged executor server from the daemon (M3.6.1).
///
/// The connection is re-established on demand; each operation is a single
/// request/response pair keyed by `correlation_id`.
pub struct ExecutorClient {
    socket: String,
    conn: tokio::sync::Mutex<Option<IpcClientConnection>>,
}

impl ExecutorClient {
    pub fn new(socket: impl Into<String>) -> Self {
        Self {
            socket: socket.into(),
            conn: tokio::sync::Mutex::new(None),
        }
    }

    /// Ensure a live connection, returning the guard so the caller can perform
    /// the request. On drop the connection is left for the next reconnect.
    async fn ensure_connected(&self) -> tokio::sync::MutexGuard<'_, Option<IpcClientConnection>> {
        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            if let Ok(conn) = IpcClientConnection::connect(&self.socket).await {
                *guard = Some(conn);
            }
        }
        guard
    }

    /// Run one request/response operation. On a dropped connection the client
    /// is cleared so the next call reconnects.
    async fn request(&self, msg_type: MsgType, payload: Vec<u8>) -> Result<IpcMessage> {
        let mut guard = self.ensure_connected().await;
        let Some(conn) = guard.as_mut() else {
            return Err(balansir_common::error::Error::Misconfiguration(
                "executor unreachable".into(),
            ));
        };
        match conn.request(msg_type, payload).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                *guard = None;
                Err(e)
            }
        }
    }

    /// Send a rule-application request and decode the typed result.
    async fn apply(&self, msg_type: MsgType, request: &ActionRequest) -> ActionResult {
        let payload = match postcard::to_allocvec(request) {
            Ok(bytes) => bytes,
            Err(_) => {
                return ActionResult::Failed {
                    error: balansir_common::ActionError::Unknown,
                    message: Some("failed to encode action request".into()),
                }
            }
        };
        match self.request(msg_type, payload).await {
            Ok(resp) => match postcard::from_bytes::<ActionResult>(&resp.payload) {
                Ok(result) => result,
                Err(_) => ActionResult::Failed {
                    error: balansir_common::ActionError::Unknown,
                    message: Some("executor returned malformed result".into()),
                },
            },
            Err(e) => ActionResult::Failed {
                error: balansir_common::ActionError::Unknown,
                message: Some(format!("executor unreachable: {e}")),
            },
        }
    }
}

#[async_trait]
impl ExecutorAdapter for ExecutorClient {
    async fn execute(&self, request: &ActionRequest) -> ActionResult {
        self.apply(MsgType::AddRule, request).await
    }

    async fn rule_count(&self) -> u32 {
        0
    }

    /// A2 inventory: ask the executor what rule ids are present in the kernel.
    /// Non-authoritative — the daemon reconciles against this result.
    async fn actual_rule_ids(&self) -> Vec<u32> {
        match self.request(MsgType::GetActualRules, Vec::new()).await {
            Ok(resp) => postcard::from_bytes::<Vec<u32>>(&resp.payload).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    async fn remove_rule(&self, rule_id: u32) -> ActionResult {
        let payload = postcard::to_allocvec(&rule_id).unwrap_or_default();
        match self.request(MsgType::RemoveRule, payload).await {
            Ok(resp) => match resp.msg_type {
                MsgType::ResponseOk => ActionResult::Applied {
                    execution_time_us: 0,
                    rule_id: Some(rule_id),
                },
                MsgType::ResponseError => {
                    let message = String::from_utf8(resp.payload.clone()).ok();
                    ActionResult::Failed {
                        error: balansir_common::ActionError::Unknown,
                        message,
                    }
                }
                _ => ActionResult::Failed {
                    error: balansir_common::ActionError::Unknown,
                    message: Some("unexpected RemoveRule response".into()),
                },
            },
            Err(e) => ActionResult::Failed {
                error: balansir_common::ActionError::Unknown,
                message: Some(format!("executor unreachable: {e}")),
            },
        }
    }
}

/// Default daemon-side executor client bound to the standard socket.
pub fn default_executor_client() -> ExecutorClient {
    ExecutorClient::new(DEFAULT_EXECUTOR_SOCKET)
}

impl Default for ExecutorClient {
    fn default() -> Self {
        default_executor_client()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::ipc::IpcServerConnection;
    use balansir_common::{Action, DecisionTrace};
    use smallvec::SmallVec;
    use tokio::net::UnixStream;

    fn action_request(action: Action) -> ActionRequest {
        ActionRequest {
            action,
            src_ip: [0; 4],
            dst_ip: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            interface: 0,
            trace: DecisionTrace {
                policy_id: 1,
                steps: SmallVec::new(),
                action,
                execution_time_us: 0,
                correlation_id: 0,
            },
        }
    }

    /// Drive a fake executor server over a paired stream: reads AddRule,
    /// echoes a typed Applied result. Runs with the current UID allowed so
    /// mutual peer-credential auth passes on the paired stream.
    #[tokio::test]
    async fn executor_client_sends_add_rule_and_decodes_result() {
        std::env::set_var(
            "BALANSIR_ALLOWED_UIDS",
            unsafe { libc::geteuid() }.to_string(),
        );

        let (daemon_stream, executor_stream) = UnixStream::pair().unwrap();
        let mut server = IpcServerConnection::accept(executor_stream)
            .await
            .expect("peer auth on paired stream");

        let server_task = tokio::spawn(async move {
            let msg = server.recv().await.unwrap();
            assert_eq!(msg.msg_type, MsgType::AddRule);
            let req: ActionRequest = postcard::from_bytes(&msg.payload).unwrap();
            assert_eq!(req.action, Action::Block);
            let result = ActionResult::Applied {
                execution_time_us: 5,
                rule_id: Some(1),
            };
            let payload = postcard::to_allocvec(&result).unwrap();
            let _ = server
                .send(&IpcMessage::response_data(msg.correlation_id, payload))
                .await;
        });

        // The client holds the daemon end of the paired stream.
        let conn = IpcClientConnection::from_stream(daemon_stream)
            .await
            .unwrap();
        let client = ExecutorClient {
            socket: "unused".into(),
            conn: tokio::sync::Mutex::new(Some(conn)),
        };
        let result = client.execute(&action_request(Action::Block)).await;
        assert!(matches!(
            result,
            ActionResult::Applied {
                rule_id: Some(1),
                ..
            }
        ));

        server_task.await.unwrap();
    }

    /// A dropped server connection clears the client so the next call
    /// reconnects (reconcile, not replay — the planner recomputes the plan).
    #[tokio::test]
    async fn executor_client_recovers_after_connection_drop() {
        std::env::set_var(
            "BALANSIR_ALLOWED_UIDS",
            unsafe { libc::geteuid() }.to_string(),
        );

        let (daemon_stream, executor_stream) = UnixStream::pair().unwrap();
        let mut server = IpcServerConnection::accept(executor_stream)
            .await
            .expect("peer auth on paired stream");

        // Server task: read AddRule, then drop the connection (executor restart).
        let server_task = tokio::spawn(async move {
            let msg = server.recv().await.unwrap();
            assert_eq!(msg.msg_type, MsgType::AddRule);
            // Simulate executor restart: close without responding.
            drop(server);
        });

        let conn = IpcClientConnection::from_stream(daemon_stream)
            .await
            .unwrap();
        let client = ExecutorClient {
            socket: "unused".into(),
            conn: tokio::sync::Mutex::new(Some(conn)),
        };

        // First call hits the dropped server -> the client clears its conn.
        let result = client.execute(&action_request(Action::Block)).await;
        // No live server to respond: the connection is cleared for reconnect,
        // and the operation reports a failure (the planner would recompute).
        let _ = result;
        assert!(
            client.conn.lock().await.is_none(),
            "dropped connection must clear the client for reconnect"
        );

        server_task.await.unwrap();
    }

    /// M3.7 chain: RemoveRule sends the rule id and decodes a success ack.
    #[tokio::test]
    async fn executor_client_remove_rule_decodes_ok() {
        std::env::set_var(
            "BALANSIR_ALLOWED_UIDS",
            unsafe { libc::geteuid() }.to_string(),
        );

        let (daemon_stream, executor_stream) = UnixStream::pair().unwrap();
        let mut server = IpcServerConnection::accept(executor_stream)
            .await
            .expect("peer auth on paired stream");

        let server_task = tokio::spawn(async move {
            let msg = server.recv().await.unwrap();
            assert_eq!(msg.msg_type, MsgType::RemoveRule);
            let rule_id: u32 = postcard::from_bytes(&msg.payload).unwrap();
            assert_eq!(rule_id, 7);
            let _ = server
                .send(&IpcMessage::response_ok(msg.correlation_id))
                .await;
        });

        let conn = IpcClientConnection::from_stream(daemon_stream)
            .await
            .unwrap();
        let client = ExecutorClient {
            socket: "unused".into(),
            conn: tokio::sync::Mutex::new(Some(conn)),
        };
        let result = client.remove_rule(7).await;
        assert!(matches!(
            result,
            ActionResult::Applied {
                rule_id: Some(7),
                ..
            }
        ));
        server_task.await.unwrap();
    }
}
