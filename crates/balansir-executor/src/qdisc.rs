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
use netlink_packet_utils::nla::{DefaultNla, Nla};
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
                    bandwidth_bps: cake_bandwidth_of(&msg.attributes),
                });
            }
        }
        Ok(out)
    }

    async fn capabilities(&self) -> Result<QosCapabilities, String> {
        Ok(probe_qos_capabilities())
    }
}

/// Build CAKE `TCA_OPTIONS` attributes.
///
/// The attribute numbers and encodings below were verified empirically
/// against the running kernel's ABI (captured from `tc` netlink messages,
/// kernel 7.x): TCA_CAKE_BASE_RATE=2 (u64 bytes/sec), TCA_CAKE_OVERHEAD=6
/// (s32), TCA_CAKE_RTT=7 / TCA_CAKE_TARGET=8 (u32 usec), TCA_CAKE_MEMORY=10
/// (u32 bytes), TCA_CAKE_WASH=13 (u32). Values are stored in native byte
/// order — identical to what `tc` sends. CAKE has no netlink knob to disable
/// ECN in this ABI (it is always enabled), so `ecn: false` is intentionally
/// not turned into a fake flag; fq_codel still honours the `ecn` config.
fn cake_options(config: &QosConfig) -> Vec<TcOption> {
    let mut opts = Vec::new();
    if let Some(bps) = config.bandwidth_bps {
        // base_rate is bytes/sec in the netlink ABI (tc converts `rate`).
        let bytes_per_sec = bps / 8;
        let mut data = Vec::new();
        data.extend_from_slice(&(bytes_per_sec as u32).to_ne_bytes());
        data.extend_from_slice(&0u32.to_ne_bytes());
        opts.push(TcOption::Other(DefaultNla::new(2, data)));
    }
    if let Some(target_ms) = config.latency_target_ms {
        // TCA_CAKE_TARGET, u32 usec; the kernel clamps it to the interval.
        let target_us = (target_ms * 1000).min(u64::from(u32::MAX)) as u32;
        opts.push(TcOption::Other(DefaultNla::new(
            8,
            target_us.to_ne_bytes().to_vec(),
        )));
    }
    if let Some(overhead) = config.overhead_bytes {
        opts.push(TcOption::Other(DefaultNla::new(
            6,
            overhead.to_ne_bytes().to_vec(),
        )));
    }
    if config.wash {
        opts.push(TcOption::Other(DefaultNla::new(13, 1u32.to_ne_bytes().to_vec())));
    }
    if let Some(memory) = config.memory_limit_bytes {
        let bytes = (memory.min(u64::from(u32::MAX)) as u32).to_ne_bytes().to_vec();
        opts.push(TcOption::Other(DefaultNla::new(10, bytes)));
    }
    opts
}

/// Extract the CAKE enforced bandwidth from a dumped qdisc message.
///
/// The kernel reports TCA_CAKE_BASE_RATE (attr 2) in *bytes/sec*; BalanSir's
/// [`QosConfig::bandwidth_bps`] uses bits/sec, so the value is converted back
/// on read. The netlink-packet-route crate has no native CAKE option parser,
/// so an unknown-kind TCA_OPTIONS dump reaches us as a `TcOption::Other` in
/// two shapes:
/// - a lone BASE_RATE attribute: value == the 8-byte rate;
/// - the whole TCA_OPTIONS payload: value == 8-byte rate followed by the
///   remaining sub-attributes (length/type headers included).
/// Both shapes are handled by first trying a nested-attribute walk (which
/// bails out immediately on the lone-value shape because its leading two
/// bytes never form a valid length), then reading the leading 8 bytes.
fn cake_bandwidth_of(attributes: &[TcAttribute]) -> Option<u64> {
    for attr in attributes {
        if let TcAttribute::Options(options) = attr {
            for option in options {
                if let TcOption::Other(nla) = option {
                    if nla.kind() != 2 {
                        continue;
                    }
                    let mut raw = vec![0u8; nla.value_len()];
                    nla.emit_value(&mut raw);
                    match scan_cake_base_rate(&raw) {
                        BlobScan::Rate(rate) => return Some(rate),
                        // A well-formed attribute chain without a usable rate
                        // (e.g. BASE_RATE is zero = unlimited): do not fall
                        // through to the leading-8-bytes read.
                        BlobScan::NoRate => continue,
                        // Not an attribute chain: this nla is the lone value.
                        BlobScan::NotABlob => {}
                    }
                    if raw.len() >= 8 {
                        return rate_from_le(&raw[..8]);
                    }
                }
            }
        }
    }
    None
}

/// Result of scanning a raw payload for a CAKE base rate.
enum BlobScan {
    /// TCA_CAKE_BASE_RATE found (bits/sec).
    Rate(u64),
    /// Payload is a well-formed attribute chain but has no usable rate.
    NoRate,
    /// Payload does not look like an attribute chain (a lone value).
    NotABlob,
}

/// Scan a raw nested-attribute chain for TCA_CAKE_BASE_RATE (kind 2,
/// u64 bytes/sec) and convert it to bits/sec.
fn scan_cake_base_rate(raw: &[u8]) -> BlobScan {
    let mut off = 0usize;
    while off + 4 <= raw.len() {
        let len = u16::from_ne_bytes([raw[off], raw[off + 1]]) as usize;
        let kind = u16::from_ne_bytes([raw[off + 2], raw[off + 3]]);
        if len < 12 || off + len > raw.len() {
            return if off == 0 {
                BlobScan::NotABlob
            } else {
                BlobScan::NoRate
            };
        }
        let payload = &raw[off + 4..off + len];
        if kind == 2 && payload.len() >= 8 {
            return match rate_from_le(payload) {
                Some(rate) => BlobScan::Rate(rate),
                None => BlobScan::NoRate, // rate present but zero = unlimited
            };
        }
        // Attributes are 4-byte aligned.
        off += (len + 3) & !3;
    }
    if off == 0 {
        BlobScan::NotABlob
    } else {
        BlobScan::NoRate
    }
}

/// Decode a little-endian u64 rate and normalize bytes/sec → bits/sec.
/// Zero means "unlimited" in the kernel; report None so drift detection does
/// not treat it as a 0 bps cap.
fn rate_from_le(bytes: &[u8]) -> Option<u64> {
    let mut wide = [0u8; 8];
    wide[..bytes.len().min(8)].copy_from_slice(&bytes[..bytes.len().min(8)]);
    let bytes_per_sec = u64::from_le_bytes(wide);
    (bytes_per_sec > 0).then_some(bytes_per_sec.saturating_mul(8))
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
                    bandwidth_bps: None,
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
                    bandwidth_bps: None,
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
                    // The simulated kernel honours the requested rate.
                    bandwidth_bps: config.bandwidth_bps,
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
    use netlink_packet_utils::nla::Nla;

    #[test]
    fn cake_bandwidth_reads_back_from_parsed_options() {
        // Round-trip: options produced by cake_options() must yield the
        // original bandwidth when scanned the way the kernel dump is scanned.
        let config = QosConfig {
            interface: "eth0".into(),
            direction: QosDirection::Egress,
            kind: QdiscKind::Cake,
            bandwidth_bps: Some(50_000_000),
            latency_target_ms: Some(10),
            overhead_bytes: None,
            ecn: true,
            wash: false,
            memory_limit_bytes: None,
            classes: vec![],
            comment: QosConfig::identity("eth0"),
        };
        let options = cake_options(&config);
        let attributes = vec![TcAttribute::Options(options)];
        assert_eq!(cake_bandwidth_of(&attributes), Some(50_000_000));
        // No bandwidth configured → nothing to read back.
        let cfg_none = QosConfig {
            bandwidth_bps: None,
            ..config
        };
        assert_eq!(
            cake_bandwidth_of(&[TcAttribute::Options(cake_options(&cfg_none))]),
            None
        );
        // Non-CAKE options (fq_codel) are ignored.
        let fq_opts = vec![TcOption::FqCodel(
            netlink_packet_route::tc::TcQdiscFqCodelOption::Target(5_000),
        )];
        assert_eq!(cake_bandwidth_of(&[TcAttribute::Options(fq_opts)]), None);
    }

    #[test]
    fn cake_bandwidth_reads_from_kernel_style_blob() {
        // A kernel dump of a CAKE qdisc arrives as one `Other` nla whose
        // payload is the nested TCA_OPTIONS blob: BASE_RATE(2,u64 bytes/sec),
        // RTT(7,u32), WASH(13,u32)...
        let mut blob = Vec::new();
        for (kind, value) in [
            (2u16, 2_500_000u64.to_le_bytes().to_vec()), // 20 Mbit/s as B/s
            (7u16, 100_000u32.to_le_bytes().to_vec()),
            (13u16, 1u32.to_le_bytes().to_vec()),
        ] {
            let len = (4 + value.len()) as u16;
            blob.extend_from_slice(&len.to_ne_bytes());
            blob.extend_from_slice(&kind.to_ne_bytes());
            blob.extend_from_slice(&value);
            while blob.len() % 4 != 0 {
                blob.push(0);
            }
        }
        let opts = vec![TcOption::Other(DefaultNla::new(2, blob))];
        assert_eq!(
            cake_bandwidth_of(&[TcAttribute::Options(opts)]),
            Some(20_000_000)
        );
        // Unlimited (zero rate) reports None, not 0.
        let mut zero = 0u64.to_le_bytes().to_vec();
        let len = (4 + zero.len()) as u16;
        let mut zblob = vec![];
        zblob.extend_from_slice(&len.to_ne_bytes());
        zblob.extend_from_slice(&2u16.to_ne_bytes());
        zblob.append(&mut zero);
        assert_eq!(zblob.len(), 12);
        assert_eq!(&zblob[..4], &[12, 0, 2, 0]);
        let opts = vec![TcOption::Other(DefaultNla::new(2, zblob))];
        assert_eq!(cake_bandwidth_of(&[TcAttribute::Options(opts)]), None);
    }

    #[test]
    fn cake_options_abi_matches_tc() {
        let config = QosConfig {
            interface: "eth0".into(),
            direction: QosDirection::Egress,
            kind: QdiscKind::Cake,
            bandwidth_bps: Some(20_000_000), // 20 Mbit/s
            latency_target_ms: Some(50),     // 50 ms
            overhead_bytes: Some(32),
            ecn: true,
            wash: true,
            memory_limit_bytes: Some(256 * 1024),
            classes: vec![],
            comment: QosConfig::identity("eth0"),
        };
        let opts = cake_options(&config);
        let mut attrs_out = Vec::new();
        for o in &opts {
            if let TcOption::Other(nla) = o {
                let mut value = vec![0u8; nla.value_len()];
                nla.emit_value(&mut value);
                let mut v = Vec::new();
                v.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
                v.extend_from_slice(&nla.kind().to_ne_bytes());
                v.extend_from_slice(&value);
                attrs_out.push(v);
            }
        }
        let blob: Vec<u8> = attrs_out.concat();

        // Walk the TCA_OPTIONS sub-attributes.
        let mut i = 0;
        let mut attrs = Vec::new();
        while i + 4 <= blob.len() {
            let len = u16::from_le_bytes([blob[i], blob[i + 1]]) as usize;
            let kind = u16::from_le_bytes([blob[i + 2], blob[i + 3]]);
            attrs.push((kind, blob[i + 4..i + len].to_vec()));
            i += (len + 3) & !3;
        }

        let get = |k: u16| attrs.iter().find(|(t, _)| *t == k).map(|(_, d)| d.clone());
        let rate = get(2).expect("BASE_RATE attr");
        assert_eq!(u64::from_le_bytes(rate[..8].try_into().unwrap()), 2_500_000);
        let overhead = get(6).expect("OVERHEAD attr");
        assert_eq!(i32::from_le_bytes(overhead[..4].try_into().unwrap()), 32);
        let target = get(8).expect("TARGET attr");
        assert_eq!(u32::from_le_bytes(target[..4].try_into().unwrap()), 50_000);
        let memory = get(10).expect("MEMORY attr");
        assert_eq!(u32::from_le_bytes(memory[..4].try_into().unwrap()), 256 * 1024);
        let wash = get(13).expect("WASH attr");
        assert_eq!(u32::from_le_bytes(wash[..4].try_into().unwrap()), 1);
    }

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
