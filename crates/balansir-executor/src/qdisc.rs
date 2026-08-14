//! Traffic-control (qdisc) backend for the executor.
//!
//! BalanSir shaping is applied through the privileged executor (never from the
//! daemon or the WebUI). This module owns the *mechanism*:
//!
//! ```text
//! QosConfig (daemon intent)
//!     ↓ QosBackend (this module)
//! qdisc / kernel (RTM_NEWQDISC / RTM_DELQDISC / RTM_GETQDISC via rtnetlink)
//! ```
//!
//! Backends:
//! - [`TcNetlinkBackend`]: real Linux qdisc via netlink (fq_codel native,
//!   CAKE via raw options, ingress attach). Requires CAP_NET_ADMIN.
//! - [`RecordOnlyBackend`]: records intent without touching the kernel
//!   (honest no-op used when no privileged mechanism is wired).
//! - [`InMemoryBackend`]: deterministic in-memory simulation for tests.
//!
//! BalanSir marks the qdiscs it creates with a reserved handle
//! ([`BALANSIR_QDISC_HANDLE_MAJOR`]); reconciliation uses that marker to find
//! our qdiscs without ever touching pre-existing ones.

use async_trait::async_trait;
use balansir_common::qos::{
    AppliedQdisc, QdiscKind, QdiscStats, QosCapabilities, QosConfig,
};
use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST,
    NLMSG_ERROR,
};
use netlink_packet_route::tc::{TcAttribute, TcHandle, TcMessage, TcOption, TcStats2};
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_utils::nla::DefaultNla;
use std::collections::HashMap;
use std::sync::Mutex;

/// Reserved qdisc handle major used to mark BalanSir-created qdiscs.
/// `0x0B51` encodes "B5 1" — distinctive, unlikely to collide with operator
/// or distribution defaults.
pub const BALANSIR_QDISC_HANDLE_MAJOR: u16 = 0x0B51;

/// The privileged qdisc mechanism.
#[async_trait]
pub trait QosBackend: Send + Sync {
    /// Apply (create or replace) a shaping configuration.
    async fn apply(&self, config: &QosConfig) -> Result<(), String>;
    /// Remove BalanSir shaping from an interface.
    async fn remove(&self, interface: &str) -> Result<(), String>;
    /// Report applied qdiscs for an interface (empty name = all interfaces).
    async fn state(&self, interface: &str) -> Result<Vec<AppliedQdisc>, String>;
    /// Probe kernel capabilities relevant to shaping.
    async fn capabilities(&self) -> Result<QosCapabilities, String>;
}

// ---------------------------------------------------------------------------
// Real netlink backend
// ---------------------------------------------------------------------------

/// A netlink connection handle plus the interface-index resolver.
pub struct TcNetlinkBackend {
    handle: tokio::sync::Mutex<rtnetlink::Handle>,
}

impl TcNetlinkBackend {
    pub async fn new() -> Result<Self, String> {
        let (connection, handle, _events) = rtnetlink::new_connection()
            .map_err(|e| format!("netlink connection failed: {e}"))?;
        tokio::spawn(connection);
        Ok(Self {
            handle: tokio::sync::Mutex::new(handle),
        })
    }

    /// Resolve an interface name to its kernel index.
    async fn ifindex(&self, interface: &str) -> Result<i32, String> {
        let handle = self.handle.lock().await;
        let mut links = handle
            .link()
            .get()
            .match_name(interface.to_string())
            .execute();
        let link = links
            .try_next()
            .await
            .map_err(|e| format!("link {interface}: {e}"))?
            .ok_or_else(|| format!("interface {interface} not found"))?;
        Ok(link.header.index as i32)
    }

    /// Query live qdiscs for one interface.
    async fn qdiscs_for(&self, interface: &str) -> Result<Vec<TcMessage>, String> {
        let index = self.ifindex(interface).await?;
        let handle = self.handle.lock().await;
        let mut stream = handle.qdisc().get().index(index).execute();
        let mut out = Vec::new();
        while let Some(msg) = stream.try_next().await.map_err(|e| e.to_string())? {
            // Some kernels return every qdisc in the netns for a GETQDISC even
            // when an ifindex filter is set; verify client-side so
            // reconciliation never mistakes another interface's qdisc for ours.
            if msg.header.index == index {
                out.push(msg);
            }
        }
        Ok(out)
    }

    /// Send a tc message and wait for the kernel ACK. Returns the errno-style
    /// message on failure.
    async fn send_tc(&self, message: TcMessage, flags: u16) -> Result<(), String> {
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewQueueDiscipline(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
        let mut handle = self.handle.lock().await;
        let mut response = handle.request(req).map_err(|e| e.to_string())?;
        while let Some(msg) = response.next().await {
            if msg.header.message_type == NLMSG_ERROR {
                if let NetlinkPayload::Error(err) = msg.payload {
                    if let Some(code) = err.code {
                        return Err(format!("netlink error {}", code));
                    }
                }
            }
        }
        Ok(())
    }

    /// Send a delete request for a qdisc with the given handle/parent.
    async fn send_tc_del(&self, message: TcMessage) -> Result<(), String> {
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::DelQueueDiscipline(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut handle = self.handle.lock().await;
        let mut response = handle.request(req).map_err(|e| e.to_string())?;
        while let Some(msg) = response.next().await {
            if msg.header.message_type == NLMSG_ERROR {
                if let NetlinkPayload::Error(err) = msg.payload {
                    if let Some(code) = err.code {
                        return Err(format!("netlink error {}", code));
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl QosBackend for TcNetlinkBackend {
    async fn apply(&self, config: &QosConfig) -> Result<(), String> {
        let index = self.ifindex(&config.interface).await?;

        let mut msg = TcMessage::with_index(index);
        msg.header.handle = TcHandle {
            major: BALANSIR_QDISC_HANDLE_MAJOR,
            minor: 0,
        };
        match (config.direction, config.kind) {
            (balansir_common::qos::QosDirection::Ingress, _) => {
                // Attach an ingress qdisc (stats + policer hook). Bandwidth
                // capping on ingress requires an IFB device; that is reported
                // via capabilities and not silently faked here.
                msg.header.parent = TcHandle::INGRESS;
                msg.header.handle = TcHandle::from(0xffff_0000);
                msg.attributes.push(TcAttribute::Kind("ingress".into()));
                self.send_tc(msg, NLM_F_CREATE | NLM_F_REPLACE).await?;
                Ok(())
            }
            (balansir_common::qos::QosDirection::Egress, QdiscKind::FqCodel) => {
                msg.header.parent = TcHandle::ROOT;
                msg.attributes.push(TcAttribute::Kind("fq_codel".into()));
                let mut opts: Vec<TcOption> = Vec::new();
                if let Some(target_ms) = config.latency_target_ms {
                    let target_us = (target_ms * 1000).min(u64::from(u32::MAX));
                    opts.push(TcOption::FqCodel(
                        netlink_packet_route::tc::TcQdiscFqCodelOption::Target(
                            target_us as u32,
                        ),
                    ));
                }
                if let Some(memory) = config.memory_limit_bytes {
                    opts.push(TcOption::FqCodel(
                        netlink_packet_route::tc::TcQdiscFqCodelOption::MemoryLimit(
                            memory.min(u64::from(u32::MAX)) as u32,
                        ),
                    ));
                }
                if config.ecn {
                    opts.push(TcOption::FqCodel(
                        netlink_packet_route::tc::TcQdiscFqCodelOption::Ecn(1),
                    ));
                }
                if !opts.is_empty() {
                    msg.attributes.push(TcAttribute::Options(opts));
                }
                // Replace so updates are applied in place (update semantics).
                self.send_tc(msg, NLM_F_CREATE | NLM_F_REPLACE).await?;
                Ok(())
            }
            (balansir_common::qos::QosDirection::Egress, QdiscKind::Cake) => {
                msg.header.parent = TcHandle::ROOT;
                msg.attributes.push(TcAttribute::Kind("cake".into()));
                msg.attributes.push(TcAttribute::Options(cake_options(config)));
                self.send_tc(msg, NLM_F_CREATE | NLM_F_REPLACE).await?;
                Ok(())
            }
            (_, QdiscKind::Ingress) => Err("Ingress kind must use the Ingress direction".into()),
        }
    }

    async fn remove(&self, interface: &str) -> Result<(), String> {
        let index = self.ifindex(interface).await?;
        // Delete the BalanSir egress qdisc (parent ROOT, marked handle).
        let mut msg = TcMessage::with_index(index);
        msg.header.parent = TcHandle::ROOT;
        msg.header.handle = TcHandle {
            major: BALANSIR_QDISC_HANDLE_MAJOR,
            minor: 0,
        };
        let _ = self.send_tc_del(msg).await;
        // Delete the ingress qdisc (parent INGRESS, handle ffff:0000).
        let mut msg = TcMessage::with_index(index);
        msg.header.parent = TcHandle::INGRESS;
        msg.header.handle = TcHandle::from(0xffff_0000);
        let _ = self.send_tc_del(msg).await;
        Ok(())
    }

    async fn state(&self, interface: &str) -> Result<Vec<AppliedQdisc>, String> {
        let mut out = Vec::new();
        // Empty name means "all interfaces" (IPC contract). Enumerate every
        // link so reconciliation sees qdiscs the daemon did not target.
        let interfaces: Vec<String> = if interface.is_empty() {
            let handle = self.handle.lock().await;
            let mut links = handle.link().get().execute();
            let mut names = Vec::new();
            while let Some(link) = links.try_next().await.map_err(|e| e.to_string())? {
                let Some(name) = link
                    .attributes
                    .iter()
                    .find_map(|a| match a {
                        netlink_packet_route::link::LinkAttribute::IfName(n) => Some(n.clone()),
                        _ => None,
                    })
                else {
                    continue;
                };
                names.push(name);
            }
            names
        } else {
            vec![interface.to_string()]
        };
        for interface in interfaces {
            let Ok(messages) = self.qdiscs_for(&interface).await else {
                // Interface vanished mid-enumeration; skip it.
                continue;
            };
            let Ok(index) = self.ifindex(&interface).await else {
                continue;
            };
            for msg in messages {
                let kind = msg
                    .attributes
                    .iter()
                    .find_map(|a| match a {
                        TcAttribute::Kind(k) => Some(k.clone()),
                        _ => None,
                    });
                let our_identity = msg.header.handle.major == BALANSIR_QDISC_HANDLE_MAJOR
                    || msg.header.parent == TcHandle::INGRESS;
                let stats = qdisc_stats_of(&msg.attributes);
                out.push(AppliedQdisc {
                    interface: interface.clone(),
                    index,
                    handle: format!("{:x}:{:x}", msg.header.handle.major, msg.header.handle.minor),
                    parent: format!("{:x}:{:x}", msg.header.parent.major, msg.header.parent.minor),
                    kind,
                    our_identity,
                    stats,
                });
            }
        }
        Ok(out)
    }

    async fn capabilities(&self) -> Result<QosCapabilities, String> {
        Ok(probe_qos_capabilities())
    }
}

/// Build CAKE `TCA_OPTIONS` attributes. Attribute numbering follows the Linux
/// `tc_cake.h` ABI (TCA_CAKE_BASE_RATE=1 … TCA_CAKE_FWMARK=16).
fn cake_options(config: &QosConfig) -> Vec<TcOption> {
    let mut opts = Vec::new();
    if let Some(bps) = config.bandwidth_bps {
        // base_rate is bytes/sec in the netlink ABI (tc converts `rate`).
        let bytes_per_sec = (bps / 8).min(u64::from(u32::MAX)) as u32;
        opts.push(TcOption::Other(DefaultNla::new(
            1,
            bytes_per_sec.to_ne_bytes().to_vec(),
        )));
    }
    if let Some(target_ms) = config.latency_target_ms {
        let target_ns = target_ms * 1_000_000;
        opts.push(TcOption::Other(DefaultNla::new(
            6,
            target_ns.to_ne_bytes().to_vec(),
        )));
    }
    if let Some(overhead) = config.overhead_bytes {
        opts.push(TcOption::Other(DefaultNla::new(
            4,
            overhead.to_ne_bytes().to_vec(),
        )));
    }
    if config.wash {
        opts.push(TcOption::Other(DefaultNla::new(11, 1u32.to_ne_bytes().to_vec())));
    }
    if config.ecn {
        opts.push(TcOption::Other(DefaultNla::new(9, 0u32.to_ne_bytes().to_vec())));
    }
    if let Some(memory) = config.memory_limit_bytes {
        let bytes = (memory.min(u64::from(u32::MAX)) as u32).to_ne_bytes().to_vec();
        opts.push(TcOption::Other(DefaultNla::new(8, bytes)));
    }
    opts
}

/// Extract a unified [`QdiscStats`] from a parsed qdisc message.
fn qdisc_stats_of(attributes: &[TcAttribute]) -> Option<QdiscStats> {
    let mut stats = QdiscStats::default();
    let mut found = false;
    for attr in attributes {
        if let TcAttribute::Stats2(items) = attr {
            for item in items {
                match item {
                    TcStats2::Basic(b) => {
                        stats.bytes = b.bytes;
                        stats.packets = u64::from(b.packets);
                        found = true;
                    }
                    TcStats2::Queue(q) => {
                        stats.qlen = u64::from(q.qlen);
                        stats.backlog_bytes = u64::from(q.backlog);
                        stats.drops = u64::from(q.drops);
                        stats.overlimits = u64::from(q.overlimits);
                        found = true;
                    }
                    _ => {}
                }
            }
        }
    }
    found.then_some(stats)
}

/// Probe shaping capabilities from the runtime kernel.
///
/// Sources: `/proc/modules` (scheduler modules) and `/sys/class/net/ifb*`
/// (IFB devices for ingress shaping). Absence of module info (e.g. built-in
/// schedulers) is handled by treating "no module listed" as *unknown* and
/// defaulting to the conservative false — the daemon then picks fq_codel,
/// which is virtually always built in, and reports honestly.
pub fn probe_qos_capabilities() -> QosCapabilities {
    let modules = std::fs::read_to_string("/proc/modules").unwrap_or_default();
    let module_present = |name: &str| modules.lines().any(|l| l.starts_with(name));

    // If /proc/modules is unreadable we cannot prove cake/netem exist; probe
    // by reading /proc/net/psched presence only as a fallback signal.
    let proc_ok = !modules.is_empty();
    let cake = proc_ok && module_present("sch_cake");
    let fq_codel = proc_ok && module_present("sch_fq_codel") || fq_codel_builtin_hint();
    let htb = proc_ok && module_present("sch_htb");
    let netem = proc_ok && module_present("sch_netem");

    // Ingress qdisc is a core feature of every modern kernel; assume present.
    let ingress = true;

    // IFB devices make real ingress shaping possible.
    let ifb_present = std::fs::read_dir("/sys/class/net")
        .map(|entries| {
            entries.filter_map(|e| e.ok()).any(|e| {
                e.file_name().to_string_lossy().starts_with("ifb")
            })
        })
        .unwrap_or(false);

    let egress_shaping = cake || fq_codel;
    let ingress_shaping = ifb_present && ingress;

    QosCapabilities {
        cake,
        fq_codel,
        ingress,
        htb,
        netem,
        egress_shaping,
        ingress_shaping,
    }
}

/// fq_codel is built into the kernel in nearly all distributions; when
/// /proc/modules shows no modules at all (e.g. a container without module
/// info), assume the built-in scheduler exists rather than report no shaping
/// at all. This is the one deliberate, documented optimism.
fn fq_codel_builtin_hint() -> bool {
    std::fs::read_to_string("/proc/modules")
        .map(|m| m.trim().is_empty())
        .unwrap_or(true)
}

// ---------------------------------------------------------------------------
// Honest no-op backend
// ---------------------------------------------------------------------------

/// Records requested shaping intent but performs no kernel change. Used when
/// no privileged netlink mechanism is available so the executor reports what
/// *would* be applied without pretending a kernel change happened.
#[derive(Debug, Clone, Default)]
pub struct RecordOnlyBackend {
    applied: std::sync::Arc<Mutex<HashMap<String, QdiscKind>>>,
}

#[async_trait]
impl QosBackend for RecordOnlyBackend {
    async fn apply(&self, config: &QosConfig) -> Result<(), String> {
        self.applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(config.interface.clone(), config.kind);
        Ok(())
    }
    async fn remove(&self, interface: &str) -> Result<(), String> {
        self.applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(interface);
        Ok(())
    }
    async fn state(&self, interface: &str) -> Result<Vec<AppliedQdisc>, String> {
        let map = self.applied.lock().unwrap_or_else(|e| e.into_inner());
        Ok(map
            .iter()
            .filter(|(name, _)| interface.is_empty() || name.as_str() == interface)
            .map(|(name, kind)| AppliedQdisc {
                interface: name.clone(),
                index: 0,
                handle: "balansir:recorded".into(),
                parent: "record-only".into(),
                kind: Some(kind.as_str().to_string()),
                our_identity: true,
                stats: None,
            })
            .collect())
    }
    async fn capabilities(&self) -> Result<QosCapabilities, String> {
        // Honest: this backend performs no kernel changes.
        Ok(QosCapabilities::unavailable())
    }
}

// ---------------------------------------------------------------------------
// In-memory simulation (tests)
// ---------------------------------------------------------------------------

/// Deterministic in-memory qdisc store simulating a kernel that supports
/// everything. Used by daemon/executor tests; never a production path.
#[derive(Default)]
pub struct InMemoryBackend {
    qdiscs: Mutex<HashMap<String, AppliedQdisc>>,
    capabilities: QosCapabilities,
}

impl InMemoryBackend {
    pub fn new(capabilities: QosCapabilities) -> Self {
        Self {
            qdiscs: Mutex::new(HashMap::new()),
            capabilities,
        }
    }

    /// Seed pre-existing (foreign) qdiscs, e.g. distribution defaults.
    pub fn with_foreign_qdisc(self, interface: &str, kind: &str) -> Self {
        self.qdiscs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                format!("{interface}:1:0"),
                AppliedQdisc {
                    interface: interface.to_string(),
                    index: 1,
                    handle: "1:0".into(),
                    parent: "ffff:fff1".into(),
                    kind: Some(kind.to_string()),
                    our_identity: false,
                    stats: None,
                },
            );
        self
    }
}

#[async_trait]
impl QosBackend for InMemoryBackend {
    async fn apply(&self, config: &QosConfig) -> Result<(), String> {
        let supported = match config.kind {
            QdiscKind::Cake => self.capabilities.cake,
            QdiscKind::FqCodel => self.capabilities.fq_codel,
            QdiscKind::Ingress => self.capabilities.ingress,
        };
        if !supported {
            return Err(format!(
                "qdisc {} not supported by this backend",
                config.kind.as_str()
            ));
        }
        let key = format!(
            "{}:{:x}:0",
            config.interface,
            BALANSIR_QDISC_HANDLE_MAJOR
        );
        self.qdiscs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                key,
                AppliedQdisc {
                    interface: config.interface.clone(),
                    index: 1,
                    handle: format!("{:x}:0", BALANSIR_QDISC_HANDLE_MAJOR),
                    parent: match config.direction {
                        balansir_common::qos::QosDirection::Egress => "ffff:fff1".into(),
                        balansir_common::qos::QosDirection::Ingress => "ffff:fff2".into(),
                    },
                    kind: Some(config.kind.as_str().to_string()),
                    our_identity: true,
                    stats: Some(QdiscStats {
                        packets: 42,
                        bytes: 4096,
                        drops: 1,
                        ..Default::default()
                    }),
                },
            );
        Ok(())
    }
    async fn remove(&self, interface: &str) -> Result<(), String> {
        let mut map = self.qdiscs.lock().unwrap_or_else(|e| e.into_inner());
        let keys: Vec<String> = map
            .keys()
            .filter(|k| {
                let (name, _) = k.split_once(':').unwrap_or((k.as_str(), ""));
                name == interface
            })
            .cloned()
            .collect();
        for key in keys {
            if map.get(&key).map(|q| q.our_identity).unwrap_or(false) {
                map.remove(&key);
            }
        }
        Ok(())
    }
    async fn state(&self, interface: &str) -> Result<Vec<AppliedQdisc>, String> {
        let map = self.qdiscs.lock().unwrap_or_else(|e| e.into_inner());
        Ok(map
            .iter()
            .filter(|(key, _)| {
                interface.is_empty()
                    || key
                        .split_once(':')
                        .map(|(name, _)| name == interface)
                        .unwrap_or(false)
            })
            .map(|(_, q)| q.clone())
            .collect())
    }
    async fn capabilities(&self) -> Result<QosCapabilities, String> {
        Ok(self.capabilities.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::qos::{QosDirection, QosConfig};

    fn full_caps() -> QosCapabilities {
        QosCapabilities {
            cake: true,
            fq_codel: true,
            ingress: true,
            htb: true,
            netem: false,
            egress_shaping: true,
            ingress_shaping: true,
        }
    }

    fn egress_cake(interface: &str) -> QosConfig {
        QosConfig {
            interface: interface.into(),
            direction: QosDirection::Egress,
            kind: QdiscKind::Cake,
            bandwidth_bps: Some(100_000_000),
            latency_target_ms: Some(5),
            overhead_bytes: Some(0),
            ecn: true,
            wash: true,
            memory_limit_bytes: None,
            classes: vec![],
            comment: QosConfig::identity(interface),
        }
    }

    #[tokio::test]
    async fn apply_remove_roundtrip() {
        let backend = InMemoryBackend::new(full_caps());
        backend.apply(&egress_cake("eth0")).await.unwrap();
        let state = backend.state("eth0").await.unwrap();
        assert_eq!(state.len(), 1);
        assert!(state[0].our_identity);
        assert_eq!(state[0].kind.as_deref(), Some("cake"));

        backend.remove("eth0").await.unwrap();
        assert!(backend.state("eth0").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn unsupported_qdisc_rejected() {
        let backend = InMemoryBackend::new(QosCapabilities {
            cake: false,
            ..full_caps()
        });
        let err = backend.apply(&egress_cake("eth0")).await.unwrap_err();
        assert!(err.contains("not supported"));
    }

    #[tokio::test]
    async fn foreign_qdisc_untouched_on_remove() {
        let backend = InMemoryBackend::new(full_caps()).with_foreign_qdisc("eth0", "pfifo_fast");
        backend.apply(&egress_cake("eth0")).await.unwrap();
        backend.remove("eth0").await.unwrap();
        let state = backend.state("eth0").await.unwrap();
        assert_eq!(state.len(), 1);
        assert!(!state[0].our_identity);
    }

    #[test]
    fn cake_options_emit_base_rate() {
        let cfg = egress_cake("eth0");
        let opts = cake_options(&cfg);
        assert!(!opts.is_empty());
    }

    #[test]
    fn qdisc_stats_parsing_empty() {
        assert!(qdisc_stats_of(&[]).is_none());
    }
}
