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
use balansir_common::ipc::{IpcMessage, IpcServerConnection, MsgType};
use balansir_common::{ActionRequest, ActionResult, PathMtu, Result};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::executor::Executor;

/// The full set of privileged mechanisms served by the executor.
///
/// Each subsystem is an allowlisted, typed mechanism; the daemon never sends
/// free-form commands. `qos`/`interface`/`tailscale` are optional by design:
/// `ExecutorServices::new` wires whatever backends are available at startup.
pub struct ExecutorServices {
    pub executor: Box<dyn Executor>,
    pub qos: Box<dyn crate::qdisc::QosBackend>,
    pub interface: Box<dyn crate::interface::InterfaceBackend>,
    pub tailscale: Box<dyn crate::tailscale::TailscaleDriver>,
}

impl ExecutorServices {
    pub fn new(
        executor: Box<dyn Executor>,
        qos: Box<dyn crate::qdisc::QosBackend>,
        interface: Box<dyn crate::interface::InterfaceBackend>,
        tailscale: Box<dyn crate::tailscale::TailscaleDriver>,
    ) -> Self {
        Self {
            executor,
            qos,
            interface,
            tailscale,
        }
    }
}

/// A concrete privileged mechanism: nftables-backed rule execution plus the
/// policy-routing (`ip rule`) capability (M3.7, ADR-014).
///
/// Maps `ActionRequest` -> `NftRuleSpec` for the supported verdicts and
/// mark actions, executing against `NftablesBackend`. `Mark` sets a real
/// fwmark (`meta mark set N`). `Route`/`Forward`/other actions have no fwmark
/// binding in the current `ActionRequest` contract and are honestly reported
/// as `Unsupported`; the `IpRuleBackend` capability (module `iprule`) is
/// implemented and unit-tested so fwmark+ip-rule is ready to wire when the
/// daemon contract can express a mark↔table pair.
///
/// Installed rules are tracked by `policy_id -> semantic fingerprint` so
/// `RemoveRule` can resolve the nft handle and delete precisely (never a
/// fragile flush-all), and `execute` can distinguish "same rule" from
/// "different rule under the same id" (A1, ADR-015).
pub struct NftablesExecutor {
    backend: crate::nftables::NftablesBackend,
    installed: Mutex<HashMap<u32, u64>>,
    /// Applied per-path MTU state (P7.2, ADR-026). The executor owns it and
    /// reports it so the daemon can reconcile; the daemon decides what *should*
    /// be applied.
    path_mtu: crate::path_mtu::PathMtuStore,
}

impl NftablesExecutor {
    pub fn new(backend: crate::nftables::NftablesBackend) -> Self {
        Self {
            backend,
            installed: Mutex::new(HashMap::new()),
            path_mtu: crate::path_mtu::PathMtuStore::new(Box::new(
                crate::path_mtu::RecordOnlyApplier,
            )),
        }
    }

    fn fingerprint_of(&self, policy_id: u32) -> Option<u64> {
        self.installed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&policy_id)
            .copied()
    }

    fn remember(&self, policy_id: u32, fingerprint: u64) {
        self.installed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(policy_id, fingerprint);
    }

    fn forget(&self, policy_id: u32) {
        self.installed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&policy_id);
    }
}

/// Stable semantic fingerprint of a rule request (A1, ADR-015).
///
/// FNV-1a over the postcard encoding of the full `ActionRequest`, so two rules
/// with the same `policy_id` but different action/flow fields hash
/// differently — "same id" is no longer assumed to mean "same rule".
fn rule_fingerprint(request: &ActionRequest) -> u64 {
    let bytes = postcard::to_allocvec(request).unwrap_or_default();
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in &bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn to_nft_verdict(action: &balansir_common::Action) -> Option<crate::nftables::NftVerdict> {
    use crate::nftables::NftVerdict;
    match action {
        balansir_common::Action::Allow => Some(NftVerdict::Accept),
        balansir_common::Action::Block => Some(NftVerdict::Drop),
        balansir_common::Action::Reject => Some(NftVerdict::Reject),
        _ => None,
    }
}

/// The stable per-rule comment used to tag installed nft rules so they can be
/// found by handle for removal. Uses the rule's `trace.policy_id` (set by the
/// daemon to the `DesiredRule.id`).
fn rule_comment(policy_id: u32) -> String {
    format!("balansir:{policy_id}")
}

fn to_nft_spec(request: &ActionRequest) -> Option<crate::nftables::NftRuleSpec> {
    use crate::nftables::NftRuleSpec;
    let verdict = to_nft_verdict(&request.action)?;
    let proto = match request.protocol {
        6 => Some(crate::nftables::NftProto::Tcp),
        17 => Some(crate::nftables::NftProto::Udp),
        _ => None,
    };
    Some(NftRuleSpec {
        proto,
        src_cidr: cidr_for_addr(&request.src_ip),
        dst_cidr: cidr_for_addr(&request.dst_ip),
        sport: (request.src_port != 0).then_some(request.src_port),
        dport: (request.dst_port != 0).then_some(request.dst_port),
        verdict,
        mark: None,
        comment: Some(rule_comment(request.trace.policy_id)),
    })
}

/// Build an nft rule for a mark action: classify the flow and set the fwmark
/// (`meta mark set N`), then allow the packet to continue so policy routing
/// (`ip rule fwmark N lookup <table>`) can take effect.
fn to_mark_spec(request: &ActionRequest, fwmark: u32) -> crate::nftables::NftRuleSpec {
    use crate::nftables::NftRuleSpec;
    let proto = match request.protocol {
        6 => Some(crate::nftables::NftProto::Tcp),
        17 => Some(crate::nftables::NftProto::Udp),
        _ => None,
    };
    NftRuleSpec {
        proto,
        src_cidr: cidr_for_addr(&request.src_ip),
        dst_cidr: cidr_for_addr(&request.dst_ip),
        sport: (request.src_port != 0).then_some(request.src_port),
        dport: (request.dst_port != 0).then_some(request.dst_port),
        verdict: crate::nftables::NftVerdict::Accept,
        mark: Some(fwmark),
        comment: Some(rule_comment(request.trace.policy_id)),
    }
}

/// Render an address as a host CIDR string, or `None` for an unspecified
/// address (no matcher). IPv6 renders as `addr/128` and is nft-rendered with
/// the `ip6` keyword (A4).
fn cidr_for_addr(addr: &std::net::IpAddr) -> Option<String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    match *addr {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED) | IpAddr::V6(Ipv6Addr::UNSPECIFIED) => None,
        IpAddr::V4(a) => Some(format!("{a}/32")),
        IpAddr::V6(a) => Some(format!("{a}/128")),
    }
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
                balansir_common::ActionType::Reject,
                balansir_common::ActionType::Mark,
            ],
            max_rules: 1024,
            max_fwmarks: 256,
            max_route_tables: 0,
        })
    }

    async fn execute(&self, request: &ActionRequest) -> ActionResult {
        let policy_id = request.trace.policy_id;
        let fingerprint = rule_fingerprint(request);

        // Idempotency (A1, ADR-015): the exact same rule is already installed.
        //
        // The fingerprint cache alone is not ground truth (P4.1, ADR-020): an
        // external kernel edit or a chain flush can remove the rule while the
        // cache still lists it. Only short-circuit when the rule is *actually
        // present in the kernel*; otherwise fall through to (re)apply so the
        // daemon's ownership loop converges instead of being swallowed by
        // stale accounting.
        if self.fingerprint_of(policy_id) == Some(fingerprint)
            && self
                .backend
                .find_handle_by_comment(&rule_comment(policy_id))
                .ok()
                .flatten()
                .is_some()
        {
            return ActionResult::AlreadyApplied;
        }

        let spec = match request.action {
            // Mark: classify + set fwmark, then continue (policy routing applies).
            balansir_common::Action::Mark { fwmark } => to_mark_spec(request, fwmark),
            _ => match to_nft_spec(request) {
                Some(spec) => spec,
                None => {
                    return ActionResult::Unsupported {
                        action_type: request.action.action_type(),
                    }
                }
            },
        };

        // Replacement under the same id: drop any prior rule first so a changed
        // rule does not leave a stale kernel rule behind.
        if self.fingerprint_of(policy_id).is_some() {
            if let Err(e) = self
                .backend
                .remove_rule_by_comment(&rule_comment(policy_id))
            {
                return ActionResult::Failed {
                    error: balansir_common::ActionError::KernelError(0),
                    message: Some(format!("replace: {e}")),
                };
            }
        }

        match self.backend.add_rule(&spec) {
            Ok(()) => {
                self.remember(policy_id, fingerprint);
                ActionResult::Applied {
                    execution_time_us: 0,
                    rule_id: Some(policy_id),
                }
            }
            Err(e) => ActionResult::Failed {
                error: balansir_common::ActionError::KernelError(0),
                message: Some(e.to_string()),
            },
        }
    }

    async fn flush(&self) -> Result<()> {
        self.backend.flush()?;
        *self.installed.lock().unwrap_or_else(|e| e.into_inner()) = HashMap::new();
        Ok(())
    }

    async fn remove_rule(&self, rule_id: u32) -> Result<()> {
        self.backend
            .remove_rule_by_comment(&rule_comment(rule_id))?;
        self.forget(rule_id);
        Ok(())
    }

    /// A2 inventory: report the rule ids currently present in the kernel. The
    /// daemon reconciles against this; the executor does not decide what should
    /// be present (non-authority).
    async fn actual_rule_ids(&self) -> Vec<u32> {
        self.backend.list_rule_ids().unwrap_or_default()
    }

    // P7.2 (ADR-026): per-path MTU. The executor owns the applied state and
    // reports it (non-authority); the daemon decides what should be applied.
    async fn set_path_mtu(&self, path: &str, mtu: u16) -> Result<()> {
        self.path_mtu
            .set(path, mtu)
            .await
            .map_err(balansir_common::Error::Fatal)
    }

    async fn restore_path_mtu(&self, path: &str) -> Result<()> {
        self.path_mtu
            .restore(path)
            .await
            .map_err(balansir_common::Error::Fatal)
    }

    async fn path_mtu_state(&self) -> Vec<PathMtu> {
        self.path_mtu.state()
    }
}

/// Allowed executor operations. Anything not in this set is rejected before
/// reaching any mechanism.
fn is_allowlisted(msg_type: MsgType) -> bool {
    matches!(
        msg_type,
        MsgType::AddRule
            | MsgType::RemoveRule
            | MsgType::FlushRules
            | MsgType::HealthCheck
            | MsgType::GetActualRules
            | MsgType::SetPathMtu
            | MsgType::RestorePathMtu
            | MsgType::GetPathMtuState
            | MsgType::QosOp
            | MsgType::GetQosState
            | MsgType::GetQosCapabilities
            | MsgType::InterfaceOp
            | MsgType::TailscaleOp
    )
}

/// Serve a single authenticated executor connection until EOF.
///
/// The executor is the privileged server (ADR-013). It accepts the daemon's
/// connection, then processes the daemon-pushed allowlisted command set. Each
/// message is validated against the allowlist, dispatched to the mechanism,
/// and answered with an explicit response. The executor never initiates
/// control.
pub async fn serve_connection(
    conn: &mut IpcServerConnection,
    services: &ExecutorServices,
) -> Result<()> {
    loop {
        let msg = conn.recv().await?;
        let response = dispatch(&msg, services).await;
        conn.send(&response).await?;
    }
}

/// Encode a postcard payload into a `ResponseData`, or a clean error.
fn data_response(
    correlation_id: balansir_common::types::CorrelationId,
    value: &impl serde::Serialize,
) -> IpcMessage {
    match postcard::to_allocvec(value) {
        Ok(payload) => IpcMessage::response_data(correlation_id, payload),
        Err(_) => IpcMessage::response_error(correlation_id, "failed to encode result"),
    }
}

/// Dispatch one allowlisted command to the mechanisms and build a response.
///
/// Used both by the server loop and by tests.
pub async fn dispatch(msg: &IpcMessage, services: &ExecutorServices) -> IpcMessage {
    if !is_allowlisted(msg.msg_type) {
        tracing::warn!(?msg.msg_type, "executor rejected non-allowlisted operation");
        return IpcMessage::response_error(msg.correlation_id, "operation not allowed");
    }

    let executor = services.executor.as_ref();
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
            let Ok(rule_id) = postcard::from_bytes::<u32>(&msg.payload) else {
                return IpcMessage::response_error(
                    msg.correlation_id,
                    "invalid RemoveRule payload",
                );
            };
            match executor.remove_rule(rule_id).await {
                Ok(()) => IpcMessage::response_ok(msg.correlation_id),
                Err(e) => IpcMessage::response_error(msg.correlation_id, &e.to_string()),
            }
        }
        MsgType::GetActualRules => {
            let ids = executor.actual_rule_ids().await;
            match postcard::to_allocvec(&ids) {
                Ok(payload) => IpcMessage::response_data(msg.correlation_id, payload),
                Err(_) => {
                    IpcMessage::response_error(msg.correlation_id, "failed to encode inventory")
                }
            }
        }
        // P7.2 (ADR-026): per-path MTU execution. The payload is a postcard
        // `PathMtu { path, mtu }` for set/restore; the executor owns the applied
        // state and reports it.
        MsgType::SetPathMtu => {
            let Ok(adj) = postcard::from_bytes::<PathMtu>(&msg.payload) else {
                return IpcMessage::response_error(
                    msg.correlation_id,
                    "invalid SetPathMtu payload",
                );
            };
            match executor.set_path_mtu(&adj.path, adj.mtu).await {
                Ok(()) => IpcMessage::response_ok(msg.correlation_id),
                Err(e) => IpcMessage::response_error(msg.correlation_id, &e.to_string()),
            }
        }
        MsgType::RestorePathMtu => {
            let Ok(adj) = postcard::from_bytes::<PathMtu>(&msg.payload) else {
                return IpcMessage::response_error(
                    msg.correlation_id,
                    "invalid RestorePathMtu payload",
                );
            };
            match executor.restore_path_mtu(&adj.path).await {
                Ok(()) => IpcMessage::response_ok(msg.correlation_id),
                Err(e) => IpcMessage::response_error(msg.correlation_id, &e.to_string()),
            }
        }
        MsgType::GetPathMtuState => {
            let state = executor.path_mtu_state().await;
            match postcard::to_allocvec(&state) {
                Ok(payload) => IpcMessage::response_data(msg.correlation_id, payload),
                Err(_) => IpcMessage::response_error(
                    msg.correlation_id,
                    "failed to encode path mtu state",
                ),
            }
        }
        // QoS: apply/remove shaping (`QosOp`), report applied state and kernel
        // capabilities. The executor is the only component that touches tc.
        MsgType::QosOp => {
            let Ok(op) = postcard::from_bytes::<balansir_common::qos::QosOp>(&msg.payload) else {
                return IpcMessage::response_error(msg.correlation_id, "invalid QosOp payload");
            };
            let result = match op {
                balansir_common::qos::QosOp::Apply(config) => {
                    match services.qos.apply(&config).await {
                        Ok(()) => balansir_common::qos::QosResult {
                            op: "apply".into(),
                            interface: config.interface.clone(),
                            ok: true,
                            detail: format!("{} applied", config.kind.as_str()),
                        },
                        Err(e) => balansir_common::qos::QosResult {
                            op: "apply".into(),
                            interface: config.interface.clone(),
                            ok: false,
                            detail: e,
                        },
                    }
                }
                balansir_common::qos::QosOp::Remove { interface } => {
                    match services.qos.remove(&interface).await {
                        Ok(()) => balansir_common::qos::QosResult {
                            op: "remove".into(),
                            interface: interface.clone(),
                            ok: true,
                            detail: "shaping removed".into(),
                        },
                        Err(e) => balansir_common::qos::QosResult {
                            op: "remove".into(),
                            interface: interface.clone(),
                            ok: false,
                            detail: e,
                        },
                    }
                }
            };
            data_response(msg.correlation_id, &result)
        }
        MsgType::GetQosState => {
            let interface = String::from_utf8(msg.payload.clone()).unwrap_or_default();
            match services.qos.state(&interface).await {
                Ok(state) => data_response(msg.correlation_id, &state),
                Err(e) => IpcMessage::response_error(msg.correlation_id, &e),
            }
        }
        MsgType::GetQosCapabilities => match services.qos.capabilities().await {
            Ok(caps) => data_response(msg.correlation_id, &caps),
            Err(e) => IpcMessage::response_error(msg.correlation_id, &e),
        },
        // Interface driver: link info + WAN MAC cloning (hardware MAC
        // preserved; validated before any netlink change).
        MsgType::InterfaceOp => {
            let Ok(op) =
                postcard::from_bytes::<balansir_common::network::InterfaceOp>(&msg.payload)
            else {
                return IpcMessage::response_error(
                    msg.correlation_id,
                    "invalid InterfaceOp payload",
                );
            };
            match op {
                balansir_common::network::InterfaceOp::Get { interface } => {
                    match services.interface.info(&interface).await {
                        Ok(infos) => data_response(msg.correlation_id, &infos),
                        Err(e) => IpcMessage::response_error(msg.correlation_id, &e),
                    }
                }
                balansir_common::network::InterfaceOp::SetMac { interface, mac } => {
                    match services.interface.set_mac(&interface, &mac).await {
                        Ok(result) => data_response(msg.correlation_id, &result),
                        Err(e) => IpcMessage::response_error(msg.correlation_id, &e),
                    }
                }
                balansir_common::network::InterfaceOp::RestoreMac { interface } => {
                    match services.interface.restore_mac(&interface).await {
                        Ok(result) => data_response(msg.correlation_id, &result),
                        Err(e) => IpcMessage::response_error(msg.correlation_id, &e),
                    }
                }
            }
        }
        // Tailscale driver: status + controlled ops. Every argument is
        // validated before any binary spawn (see tailscale.rs).
        MsgType::TailscaleOp => {
            let Ok(op) =
                postcard::from_bytes::<balansir_common::network::TailscaleOp>(&msg.payload)
            else {
                return IpcMessage::response_error(
                    msg.correlation_id,
                    "invalid TailscaleOp payload",
                );
            };
            match op {
                balansir_common::network::TailscaleOp::Status => {
                    data_response(msg.correlation_id, &services.tailscale.status().await)
                }
                balansir_common::network::TailscaleOp::Up { auth_key } => data_response(
                    msg.correlation_id,
                    &services.tailscale.up(auth_key.as_deref()).await,
                ),
                balansir_common::network::TailscaleOp::Down => {
                    data_response(msg.correlation_id, &services.tailscale.down().await)
                }
                balansir_common::network::TailscaleOp::Reconnect => {
                    data_response(msg.correlation_id, &services.tailscale.reconnect().await)
                }
                balansir_common::network::TailscaleOp::SetRoutes { routes, exit_node } => {
                    data_response(
                        msg.correlation_id,
                        &services.tailscale.set_routes(&routes, exit_node).await,
                    )
                }
            }
        }
        _ => IpcMessage::response_error(msg.correlation_id, "operation not allowed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::ipc::IpcMessage;
    use balansir_common::qos::{QdiscKind, QosCapabilities, QosConfig, QosDirection};

    /// A fully-wired service bundle for tests: DummyExecutor for rules,
    /// InMemoryBackend for QoS, SysfsInterfaceBackend for interfaces and
    /// MockTailscaleDriver for Tailscale.
    fn dummy_services() -> ExecutorServices {
        ExecutorServices::new(
            Box::new(crate::executor::DummyExecutor::new()),
            Box::new(crate::qdisc::InMemoryBackend::new(QosCapabilities {
                cake: true,
                fq_codel: true,
                ingress: true,
                htb: true,
                netem: false,
                egress_shaping: true,
                ingress_shaping: true,
            })),
            Box::new(crate::interface::SysfsInterfaceBackend),
            Box::new(crate::tailscale::MockTailscaleDriver::new(
                balansir_common::network::TailscaleStatus {
                    installed: true,
                    backend_state: "Running".into(),
                    summary: "mock".into(),
                    ..Default::default()
                },
            )),
        )
    }

    fn message(msg_type: MsgType, payload: Vec<u8>) -> IpcMessage {
        IpcMessage::new(msg_type, 1, payload)
    }

    #[tokio::test]
    async fn health_check_is_allowlisted() {
        let response = dispatch(&message(MsgType::HealthCheck, vec![]), &dummy_services()).await;
        assert_eq!(response.msg_type, MsgType::ResponseOk);
    }

    /// A2: GetActualRules returns the executor's kernel inventory (non-
    /// authoritative). DummyExecutor's inventory is empty.
    #[tokio::test]
    async fn get_actual_rules_returns_inventory() {
        let response = dispatch(&message(MsgType::GetActualRules, vec![]), &dummy_services()).await;
        assert_eq!(response.msg_type, MsgType::ResponseData);
        let ids: Vec<u32> = postcard::from_bytes(&response.payload).unwrap();
        assert!(ids.is_empty());
    }

    /// P7.2: SetPathMtu / RestorePathMtu / GetPathMtuState are allowlisted and
    /// return typed results. DummyExecutor doesn't implement MTU, so set fails
    /// honestly as Unsupported; state is empty.
    #[tokio::test]
    async fn path_mtu_ops_dispatch() {
        // DummyExecutor does not implement set_path_mtu -> honest error.
        let adj = PathMtu {
            path: "example.com".into(),
            mtu: 1400,
        };
        let set_payload = postcard::to_allocvec(&adj).unwrap();
        let resp = dispatch(
            &message(MsgType::SetPathMtu, set_payload),
            &dummy_services(),
        )
        .await;
        assert_eq!(resp.msg_type, MsgType::ResponseError);

        let state = dispatch(
            &message(MsgType::GetPathMtuState, vec![]),
            &dummy_services(),
        )
        .await;
        assert_eq!(state.msg_type, MsgType::ResponseData);
        let mtu: Vec<PathMtu> = postcard::from_bytes(&state.payload).unwrap();
        assert!(mtu.is_empty());
    }

    /// QoS: apply/remove via QosOp against the in-memory backend.
    #[tokio::test]
    async fn qos_op_apply_and_remove() {
        let services = dummy_services();
        let cfg = QosConfig {
            interface: "eth0".into(),
            direction: QosDirection::Egress,
            kind: QdiscKind::Cake,
            bandwidth_bps: Some(100_000_000),
            latency_target_ms: None,
            overhead_bytes: None,
            ecn: true,
            wash: false,
            memory_limit_bytes: None,
            classes: vec![],
            comment: QosConfig::identity("eth0"),
        };
        let payload = postcard::to_allocvec(&balansir_common::qos::QosOp::Apply(cfg)).unwrap();
        let resp = dispatch(&message(MsgType::QosOp, payload), &services).await;
        assert_eq!(resp.msg_type, MsgType::ResponseData);
        let result: balansir_common::qos::QosResult = postcard::from_bytes(&resp.payload).unwrap();
        assert!(result.ok);

        // State reports the applied qdisc.
        let state = dispatch(&message(MsgType::GetQosState, b"eth0".to_vec()), &services).await;
        let qdiscs: Vec<balansir_common::qos::AppliedQdisc> =
            postcard::from_bytes(&state.payload).unwrap();
        assert_eq!(qdiscs.len(), 1);
        assert!(qdiscs[0].our_identity);

        // Remove.
        let payload = postcard::to_allocvec(&balansir_common::qos::QosOp::Remove {
            interface: "eth0".into(),
        })
        .unwrap();
        let resp = dispatch(&message(MsgType::QosOp, payload), &services).await;
        let result: balansir_common::qos::QosResult = postcard::from_bytes(&resp.payload).unwrap();
        assert!(result.ok);
    }

    /// QoS capabilities are reported through the boundary.
    #[tokio::test]
    async fn qos_capabilities_dispatch() {
        let resp = dispatch(
            &message(MsgType::GetQosCapabilities, vec![]),
            &dummy_services(),
        )
        .await;
        assert_eq!(resp.msg_type, MsgType::ResponseData);
        let caps: QosCapabilities = postcard::from_bytes(&resp.payload).unwrap();
        assert!(caps.cake);
    }

    /// Tailscale: status + a controlled op return typed results.
    #[tokio::test]
    async fn tailscale_ops_dispatch() {
        let services = dummy_services();
        let status_payload =
            postcard::to_allocvec(&balansir_common::network::TailscaleOp::Status).unwrap();
        let status = dispatch(&message(MsgType::TailscaleOp, status_payload), &services).await;
        assert_eq!(status.msg_type, MsgType::ResponseData);
        // Status payload must be a TailscaleStatus.
        let decoded: balansir_common::network::TailscaleStatus =
            postcard::from_bytes(&status.payload).unwrap();
        assert_eq!(decoded.backend_state, "Running");

        let up = balansir_common::network::TailscaleOp::Up { auth_key: None };
        let payload = postcard::to_allocvec(&up).unwrap();
        let resp = dispatch(&message(MsgType::TailscaleOp, payload), &services).await;
        let result: balansir_common::network::TailscaleResult =
            postcard::from_bytes(&resp.payload).unwrap();
        assert!(result.ok);
    }

    /// Interface driver: sysfs info for the loopback must be present.
    #[tokio::test]
    async fn interface_op_info_dispatch() {
        let services = dummy_services();
        let op = balansir_common::network::InterfaceOp::Get {
            interface: "lo".into(),
        };
        let payload = postcard::to_allocvec(&op).unwrap();
        let resp = dispatch(&message(MsgType::InterfaceOp, payload), &services).await;
        assert_eq!(resp.msg_type, MsgType::ResponseData);
        let infos: Vec<balansir_common::network::InterfaceInfo> =
            postcard::from_bytes(&resp.payload).unwrap();
        assert!(!infos.is_empty());
    }

    #[tokio::test]
    async fn add_rule_with_invalid_payload_is_rejected() {
        let response = dispatch(&message(MsgType::AddRule, vec![1, 2, 3]), &dummy_services()).await;
        assert_eq!(response.msg_type, MsgType::ResponseError);
    }

    #[tokio::test]
    async fn add_rule_with_valid_payload_returns_typed_result() {
        let request = ActionRequest {
            action: balansir_common::Action::Block,
            src_ip: std::net::IpAddr::from([0, 0, 0, 0]),
            dst_ip: std::net::IpAddr::from([0, 0, 0, 0]),
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
        let response = dispatch(&message(MsgType::AddRule, payload), &dummy_services()).await;
        assert_eq!(response.msg_type, MsgType::ResponseData);
        let result: ActionResult = postcard::from_bytes(&response.payload).unwrap();
        assert!(matches!(result, ActionResult::Applied { .. }));
    }

    #[tokio::test]
    async fn remove_rule_is_allowlisted_but_dummy_not_implemented() {
        // Valid rule id payload; the DummyExecutor's remove_rule is the
        // default not-implemented, so the daemon sees an explicit error rather
        // than a fabricated success.
        let payload = postcard::to_allocvec(&7u32).unwrap();
        let response = dispatch(&message(MsgType::RemoveRule, payload), &dummy_services()).await;
        assert_eq!(response.msg_type, MsgType::ResponseError);
        let err = String::from_utf8(response.payload.clone()).unwrap();
        assert!(err.contains("not implemented"));
    }

    #[tokio::test]
    async fn remove_rule_with_invalid_payload_is_rejected() {
        let response = dispatch(
            &message(MsgType::RemoveRule, vec![1, 2, 3]),
            &dummy_services(),
        )
        .await;
        assert_eq!(response.msg_type, MsgType::ResponseError);
    }

    #[tokio::test]
    async fn flush_rules_dispatches() {
        // DummyExecutor's flush is a no-op success; the point is the op is
        // allowlisted and dispatched (not rejected).
        let response = dispatch(&message(MsgType::FlushRules, vec![]), &dummy_services()).await;
        assert_eq!(response.msg_type, MsgType::ResponseOk);
    }

    #[test]
    fn nft_spec_maps_supported_actions() {
        use crate::nftables::NftVerdict;

        let block = ActionRequest {
            action: balansir_common::Action::Block,
            src_ip: std::net::IpAddr::from([10, 0, 0, 1]),
            dst_ip: std::net::IpAddr::from([0, 0, 0, 0]),
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
            src_ip: std::net::IpAddr::from([0, 0, 0, 0]),
            dst_ip: std::net::IpAddr::from([0, 0, 0, 0]),
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
            src_ip: std::net::IpAddr::from([0, 0, 0, 0]),
            dst_ip: std::net::IpAddr::from([0, 0, 0, 0]),
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

    /// A4 (ADR-017): IPv6 is representable — a v6 source renders as an
    /// `ip6 saddr <addr>/128` matcher; unspecified addresses render no matcher.
    #[test]
    fn nft_spec_renders_ipv6_src_as_ip6_saddr() {
        let v6 = ActionRequest {
            action: balansir_common::Action::Block,
            src_ip: std::net::IpAddr::V6("2001:db8::1".parse().unwrap()),
            dst_ip: std::net::IpAddr::V6("2001:db8::2".parse().unwrap()),
            src_port: 0,
            dst_port: 443,
            protocol: 6,
            interface: 0,
            trace: balansir_common::DecisionTrace {
                policy_id: 9,
                steps: smallvec::SmallVec::new(),
                action: balansir_common::Action::Block,
                execution_time_us: 0,
                correlation_id: 0,
            },
        };
        let spec = to_nft_spec(&v6).expect("v6 Block must map to a spec");
        assert_eq!(spec.src_cidr.as_deref(), Some("2001:db8::1/128"));
        assert!(spec.render().contains(&"ip6".to_string()));
        assert!(spec.render().contains(&"2001:db8::1/128".to_string()));

        // Unspecified v6 is "no matcher", same as unspecified v4.
        let unspecified_v6 = ActionRequest {
            src_ip: std::net::IpAddr::V6("::".parse().unwrap()),
            ..v6
        };
        assert!(to_nft_spec(&unspecified_v6)
            .expect("Block must map to a spec")
            .src_cidr
            .is_none());
    }

    /// A1 (ADR-015): the rule fingerprint is deterministic and distinguishes
    /// "same rule" from "different rule under the same id".
    #[test]
    fn rule_fingerprint_is_stable_and_semantic() {
        let mut base = ActionRequest {
            action: balansir_common::Action::Block,
            src_ip: std::net::IpAddr::from([10, 0, 0, 1]),
            dst_ip: std::net::IpAddr::from([0, 0, 0, 0]),
            src_port: 0,
            dst_port: 443,
            protocol: 6,
            interface: 0,
            trace: balansir_common::DecisionTrace {
                policy_id: 42,
                steps: smallvec::SmallVec::new(),
                action: balansir_common::Action::Block,
                execution_time_us: 0,
                correlation_id: 0,
            },
        };
        let fp = rule_fingerprint(&base);
        // Same content -> same fingerprint.
        assert_eq!(rule_fingerprint(&base), fp);

        // Same id, different action -> different fingerprint ("same id != same rule").
        base.action = balansir_common::Action::Allow;
        assert_ne!(rule_fingerprint(&base), fp);
    }
}
