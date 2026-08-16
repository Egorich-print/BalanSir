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
use balansir_common::gateway::{GatewayConfig, GatewayResult, GatewayStatus};
use balansir_common::ipc::{IpcClientConnection, IpcMessage, MsgType};
use balansir_common::network::{
    InterfaceInfo, InterfaceOp, InterfaceResult, TailscaleOp, TailscaleResult, TailscaleStatus,
};
use balansir_common::qos::{AppliedQdisc, QosCapabilities, QosOp, QosResult};
use balansir_common::{ActionRequest, ActionResult, PathMtu, Result, UpnpOp, UpnpOpResult};

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

    // ------------------------------------------------------------------
    // QoS / interface / tailscale subsystem ops (same typed IPC boundary)
    // ------------------------------------------------------------------

    /// Encode `value` as a postcard payload, or return a clean error.
    fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
        postcard::to_allocvec(value)
            .map_err(|e| balansir_common::error::Error::Fatal(format!("encode: {e}")))
    }

    /// Decode the response payload as `T`, mapping errors to a clean failure.
    fn decode<T: serde::de::DeserializeOwned>(resp: &IpcMessage) -> Result<T> {
        postcard::from_bytes(&resp.payload)
            .map_err(|e| balansir_common::error::Error::Fatal(format!("decode: {e}")))
    }

    /// A typed request whose success is `ResponseOk`/`ResponseData`.
    async fn typed_request(
        &self,
        msg_type: MsgType,
        payload: Vec<u8>,
        op: &str,
    ) -> Result<IpcMessage> {
        let resp = self.request(msg_type, payload).await?;
        match resp.msg_type {
            MsgType::ResponseOk | MsgType::ResponseData => Ok(resp),
            MsgType::ResponseError => Err(balansir_common::error::Error::Fatal(format!(
                "executor rejected {op}: {}",
                String::from_utf8_lossy(&resp.payload)
            ))),
            _ => Err(balansir_common::error::Error::Fatal(format!(
                "unexpected {op} response"
            ))),
        }
    }

    /// Apply (or remove) a shaping configuration.
    pub async fn qos_op(&self, op: &QosOp) -> Result<QosResult> {
        let payload = Self::encode(op)?;
        let resp = self.typed_request(MsgType::QosOp, payload, "QosOp").await?;
        Self::decode(&resp)
    }

    /// Report applied qdiscs (empty interface = all).
    pub async fn qos_state(&self, interface: &str) -> Result<Vec<AppliedQdisc>> {
        let resp = self
            .typed_request(
                MsgType::GetQosState,
                interface.as_bytes().to_vec(),
                "GetQosState",
            )
            .await?;
        Self::decode(&resp)
    }

    /// Kernel shaping capabilities.
    pub async fn qos_capabilities(&self) -> Result<QosCapabilities> {
        let resp = self
            .typed_request(
                MsgType::GetQosCapabilities,
                Vec::new(),
                "GetQosCapabilities",
            )
            .await?;
        Self::decode(&resp)
    }

    /// Interface link info.
    pub async fn interface_info(&self, interface: &str) -> Result<Vec<InterfaceInfo>> {
        let op = InterfaceOp::Get {
            interface: interface.to_string(),
        };
        let payload = Self::encode(&op)?;
        let resp = self
            .typed_request(MsgType::InterfaceOp, payload, "InterfaceOp")
            .await?;
        Self::decode(&resp)
    }

    /// WAN MAC cloning. The executor preserves the factory MAC for restore.
    pub async fn interface_set_mac(&self, interface: &str, mac: &str) -> Result<InterfaceResult> {
        let op = InterfaceOp::SetMac {
            interface: interface.to_string(),
            mac: mac.to_string(),
        };
        let payload = Self::encode(&op)?;
        let resp = self
            .typed_request(MsgType::InterfaceOp, payload, "InterfaceOp")
            .await?;
        Self::decode(&resp)
    }

    /// Restore the factory (hardware) MAC.
    pub async fn interface_restore_mac(&self, interface: &str) -> Result<InterfaceResult> {
        let op = InterfaceOp::RestoreMac {
            interface: interface.to_string(),
        };
        let payload = Self::encode(&op)?;
        let resp = self
            .typed_request(MsgType::InterfaceOp, payload, "InterfaceOp")
            .await?;
        Self::decode(&resp)
    }

    /// Apply the gateway datapath (NAT, IP forwarding, conntrack, management
    /// firewall). The executor renders the real nftables/sysctl rules.
    pub async fn gateway_apply(&self, cfg: &GatewayConfig) -> Result<GatewayResult> {
        let payload = Self::encode(&balansir_common::gateway::GatewayOp::Apply(cfg.clone()))?;
        let resp = self
            .typed_request(MsgType::GatewayOp, payload, "GatewayOp")
            .await?;
        Self::decode(&resp)
    }

    /// Remove the gateway datapath the executor installed.
    pub async fn gateway_remove(&self) -> Result<GatewayResult> {
        let payload = Self::encode(&balansir_common::gateway::GatewayOp::Remove)?;
        let resp = self
            .typed_request(MsgType::GatewayOp, payload, "GatewayOp")
            .await?;
        Self::decode(&resp)
    }

    /// Report the currently applied gateway datapath state.
    pub async fn gateway_status(&self) -> Result<GatewayStatus> {
        let payload = Self::encode(&balansir_common::gateway::GatewayOp::Status)?;
        let resp = self
            .typed_request(MsgType::GatewayOp, payload, "GatewayOp")
            .await?;
        Self::decode(&resp)
    }

    /// Install an UPnP/IGD DNAT port mapping in the executor's `nat prerouting`
    /// chain. The daemon runs the IGD control point (SSDP/SOAP); the executor
    /// owns the kernel rules.
    pub async fn upnp_add(
        &self,
        external_port: u16,
        proto: &str,
        internal_ip: &str,
        internal_port: u16,
        wan_interface: &str,
    ) -> Result<UpnpOpResult> {
        let payload = Self::encode(&UpnpOp::AddPortMapping {
            external_port,
            proto: proto.to_string(),
            internal_ip: internal_ip.to_string(),
            internal_port,
            wan_interface: wan_interface.to_string(),
        })?;
        let resp = self
            .typed_request(MsgType::UpnpOp, payload, "UpnpOp")
            .await?;
        Self::decode(&resp)
    }

    /// Remove an UPnP DNAT port mapping.
    pub async fn upnp_remove(
        &self,
        external_port: u16,
        proto: &str,
        wan_interface: &str,
    ) -> Result<UpnpOpResult> {
        let payload = Self::encode(&UpnpOp::RemovePortMapping {
            external_port,
            proto: proto.to_string(),
            wan_interface: wan_interface.to_string(),
        })?;
        let resp = self
            .typed_request(MsgType::UpnpOp, payload, "UpnpOp")
            .await?;
        Self::decode(&resp)
    }

    /// Remove every UPnP-installed mapping.
    pub async fn upnp_remove_all(&self) -> Result<UpnpOpResult> {
        let payload = Self::encode(&UpnpOp::RemoveAll)?;
        let resp = self
            .typed_request(MsgType::UpnpOp, payload, "UpnpOp")
            .await?;
        Self::decode(&resp)
    }

    /// Tailscale status.
    pub async fn tailscale_status(&self) -> Result<TailscaleStatus> {
        let op = TailscaleOp::Status;
        let payload = Self::encode(&op)?;
        let resp = self
            .typed_request(MsgType::TailscaleOp, payload, "TailscaleOp")
            .await?;
        Self::decode(&resp)
    }

    /// Tailscale bring-up (optional auth key).
    pub async fn tailscale_up(&self, auth_key: Option<String>) -> Result<TailscaleResult> {
        let op = TailscaleOp::Up { auth_key };
        let payload = Self::encode(&op)?;
        let resp = self
            .typed_request(MsgType::TailscaleOp, payload, "TailscaleOp")
            .await?;
        Self::decode(&resp)
    }

    /// Tailscale tear-down.
    pub async fn tailscale_down(&self) -> Result<TailscaleResult> {
        let op = TailscaleOp::Down;
        let payload = Self::encode(&op)?;
        let resp = self
            .typed_request(MsgType::TailscaleOp, payload, "TailscaleOp")
            .await?;
        Self::decode(&resp)
    }

    /// Tailscale reconnect.
    pub async fn tailscale_reconnect(&self) -> Result<TailscaleResult> {
        let op = TailscaleOp::Reconnect;
        let payload = Self::encode(&op)?;
        let resp = self
            .typed_request(MsgType::TailscaleOp, payload, "TailscaleOp")
            .await?;
        Self::decode(&resp)
    }

    /// Advertise subnet routes / exit node.
    pub async fn tailscale_set_routes(
        &self,
        routes: &[String],
        exit_node: bool,
    ) -> Result<TailscaleResult> {
        let op = TailscaleOp::SetRoutes {
            routes: routes.to_vec(),
            exit_node,
        };
        let payload = Self::encode(&op)?;
        let resp = self
            .typed_request(MsgType::TailscaleOp, payload, "TailscaleOp")
            .await?;
        Self::decode(&resp)
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

    // P7.2 (ADR-026): per-path MTU execution over the existing IPC boundary.
    async fn set_path_mtu(&self, path: &str, mtu: u16) -> Result<()> {
        let adj = PathMtu {
            path: path.to_string(),
            mtu,
        };
        let payload = postcard::to_allocvec(&adj)
            .map_err(|e| balansir_common::error::Error::Fatal(format!("encode: {e}")))?;
        let resp = self.request(MsgType::SetPathMtu, payload).await?;
        match resp.msg_type {
            MsgType::ResponseOk => Ok(()),
            MsgType::ResponseError => Err(balansir_common::error::Error::Fatal(format!(
                "executor rejected SetPathMtu: {}",
                String::from_utf8_lossy(&resp.payload)
            ))),
            _ => Err(balansir_common::error::Error::Fatal(
                "unexpected SetPathMtu response".into(),
            )),
        }
    }

    async fn restore_path_mtu(&self, path: &str) -> Result<()> {
        let adj = PathMtu {
            path: path.to_string(),
            mtu: 0,
        };
        let payload = postcard::to_allocvec(&adj)
            .map_err(|e| balansir_common::error::Error::Fatal(format!("encode: {e}")))?;
        let resp = self.request(MsgType::RestorePathMtu, payload).await?;
        match resp.msg_type {
            MsgType::ResponseOk => Ok(()),
            MsgType::ResponseError => Err(balansir_common::error::Error::Fatal(format!(
                "executor rejected RestorePathMtu: {}",
                String::from_utf8_lossy(&resp.payload)
            ))),
            _ => Err(balansir_common::error::Error::Fatal(
                "unexpected RestorePathMtu response".into(),
            )),
        }
    }

    async fn path_mtu_state(&self) -> Vec<PathMtu> {
        match self.request(MsgType::GetPathMtuState, Vec::new()).await {
            Ok(resp) => postcard::from_bytes::<Vec<PathMtu>>(&resp.payload).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    async fn dpi_op(&self, op: &balansir_common::DpiOp) -> Result<balansir_common::DpiOpResult> {
        let payload = postcard::to_allocvec(op)
            .map_err(|e| balansir_common::error::Error::Fatal(format!("encode: {e}")))?;
        let resp = self.request(MsgType::DpiOp, payload).await?;
        match resp.msg_type {
            MsgType::ResponseData => postcard::from_bytes(&resp.payload).map_err(|e| {
                balansir_common::error::Error::Fatal(format!("decode DpiOpResult: {e}"))
            }),
            MsgType::ResponseError => Err(balansir_common::error::Error::Fatal(format!(
                "executor rejected DpiOp: {}",
                String::from_utf8_lossy(&resp.payload)
            ))),
            _ => Err(balansir_common::error::Error::Fatal(
                "unexpected DpiOp response".into(),
            )),
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
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
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

    /// P7.2 (ADR-026): SetPathMtu round-trips over the existing IPC boundary —
    /// the daemon sends a PathMtu, the executor acks, and GetPathMtuState
    /// reports the applied set (non-authority).
    #[tokio::test]
    async fn executor_client_set_and_query_path_mtu_roundtrip() {
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
            assert_eq!(msg.msg_type, MsgType::SetPathMtu);
            let adj: PathMtu = postcard::from_bytes(&msg.payload).unwrap();
            assert_eq!(adj.path, "example.com");
            assert_eq!(adj.mtu, 1400);
            let _ = server
                .send(&IpcMessage::response_ok(msg.correlation_id))
                .await;

            let state_msg = server.recv().await.unwrap();
            assert_eq!(state_msg.msg_type, MsgType::GetPathMtuState);
            let state = vec![PathMtu {
                path: "example.com".into(),
                mtu: 1400,
            }];
            let payload = postcard::to_allocvec(&state).unwrap();
            let _ = server
                .send(&IpcMessage::response_data(
                    state_msg.correlation_id,
                    payload,
                ))
                .await;
        });

        let conn = IpcClientConnection::from_stream(daemon_stream)
            .await
            .unwrap();
        let client = ExecutorClient {
            socket: "unused".into(),
            conn: tokio::sync::Mutex::new(Some(conn)),
        };

        client.set_path_mtu("example.com", 1400).await.unwrap();
        let state = client.path_mtu_state().await;
        assert_eq!(state.len(), 1);
        assert_eq!(state[0].path, "example.com");
        assert_eq!(state[0].mtu, 1400);

        server_task.await.unwrap();
    }
}
