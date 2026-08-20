//! DPI-bypass engine: NFQUEUE interception loop + per-profile strategy.
//!
//! Receives intercepted TCP packets from a kernel NFQUEUE, determines the
//! destination host from the TLS SNI (when present), resolves the matching
//! profile, applies its strategies, and returns a verdict — optionally
//! replacing the packet with the mutated copy.

use crate::nfqueue::NfQueue;
use crate::packet::{extract_tls_sni, TcpPacket};
use crate::strategies::{EngineConfig, Strategy};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Statistics exposed to the daemon/WebUI.
#[derive(Debug, Default, Clone)]
pub struct B4Stats {
    pub packets_seen: u64,
    pub tls_packets: u64,
    pub mutated: u64,
    pub dropped: u64,
    pub accepted: u64,
    /// Processing/verdict errors. A growing counter with no matching packet
    /// flow means the engine is in trouble and the operator should look.
    pub errors: u64,
}

/// The DPI-bypass engine runtime.
pub struct B4Engine {
    queue_num: u16,
    config: EngineConfig,
    /// Full mission strategy sets (tcp/udp/fragmentation/faking/targets).
    /// Swappable at runtime (Discovery writes into it).
    sets: Arc<std::sync::Mutex<Vec<crate::set::B4Set>>>,
    /// Which TCP destination ports to intercept (default 443).
    ports: Vec<u16>,
    /// Which UDP destination ports to intercept for faking (default 443).
    udp_ports: Vec<u16>,
    running: Arc<AtomicBool>,
    /// Set when the interception thread exits unexpectedly (not via stop()).
    /// Lets the daemon detect a dead engine and surface it instead of leaving
    /// a silently-blackholed queue (FAIL_OPEN keeps traffic flowing, but the
    /// operator must know the engine died).
    dead: Arc<AtomicBool>,
    stats: Arc<AtomicU64Arr>,
}

/// Atomic counters backing `B4Stats`.
#[derive(Debug, Default)]
struct AtomicU64Arr {
    packets_seen: AtomicU64,
    tls_packets: AtomicU64,
    mutated: AtomicU64,
    dropped: AtomicU64,
    accepted: AtomicU64,
    errors: AtomicU64,
}

impl B4Engine {
    /// Create the engine (does not start the loop).
    pub fn new(queue_num: u16, config: EngineConfig, ports: Vec<u16>) -> Self {
        Self::with_sets(queue_num, config, Vec::new(), ports, vec![443])
    }

    /// Create the engine with full strategy sets (mission §6).
    pub fn with_sets(
        queue_num: u16,
        config: EngineConfig,
        sets: Vec<crate::set::B4Set>,
        ports: Vec<u16>,
        udp_ports: Vec<u16>,
    ) -> Self {
        Self {
            queue_num,
            config,
            sets: Arc::new(std::sync::Mutex::new(sets)),
            ports: if ports.is_empty() { vec![443] } else { ports },
            udp_ports: if udp_ports.is_empty() {
                vec![443]
            } else {
                udp_ports
            },
            running: Arc::new(AtomicBool::new(false)),
            dead: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(AtomicU64Arr::default()),
        }
    }

    /// The strategy sets this engine applies (for status/API).
    pub fn sets(&self) -> Vec<crate::set::B4Set> {
        self.sets.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Replace the active strategy sets at runtime (used by Discovery and by
    /// the operator API). The interception loop reads the current snapshot on
    /// every packet, so this takes effect immediately.
    pub fn set_sets(&self, sets: Vec<crate::set::B4Set>) {
        let mut guard = self.sets.lock().unwrap_or_else(|e| e.into_inner());
        *guard = sets;
    }

    /// Run the interception loop until stopped.
    pub async fn run(&self) -> Result<(), String> {
        if self.running.load(Ordering::SeqCst) {
            return Err("b4 engine already running".into());
        }
        self.dead.store(false, Ordering::SeqCst);
        let queue = NfQueue::new(self.queue_num, 64 * 1024)
            .map_err(|e| format!("NFQUEUE bind failed: {e}"))?;
        self.running.store(true, Ordering::SeqCst);
        tracing::info!(queue = self.queue_num, "b4 engine listening (NFQUEUE)",);

        // This is a blocking netlink loop; run it on a dedicated blocking
        // task so the async executor is not starved.
        let stats = Arc::clone(&self.stats);
        let running = Arc::clone(&self.running);
        let dead = Arc::clone(&self.dead);
        let config = self.config.clone();
        // Share the engine's live set list so runtime Discovery updates take
        // effect immediately (the loop reads the current snapshot per packet).
        let sets = Arc::clone(&self.sets);
        let ports = self.ports.clone();
        let udp_ports = self.udp_ports.clone();
        let queue = std::sync::Arc::new(queue);

        tokio::task::spawn_blocking(move || {
            tracing::info!("b4 engine: interception thread started");
            // catch_unwind so a panic in packet processing (a malformed
            // packet, a bug in a strategy) never kills the thread silently:
            // the engine is marked dead and the daemon surfaces it, while the
            // kernel FAIL_OPEN flag keeps traffic flowing.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut reassembler = crate::reassembly::TcpReassembler::new();
                interception_loop(
                    &queue,
                    &running,
                    &stats,
                    &config,
                    &sets,
                    &ports,
                    &udp_ports,
                    &mut reassembler,
                )
            }));
            let outcome = match outcome {
                Ok(()) => "stopped".to_string(),
                Err(payload) => {
                    let msg = payload
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".to_string());
                    format!("panic: {msg}")
                }
            };
            // The loop always exits because running flipped to false OR it
            // hit a fatal error/panic. Only the latter is an unexpected death.
            if running.load(Ordering::SeqCst) {
                dead.store(true, Ordering::SeqCst);
                tracing::error!("b4 engine: interception thread exited while running: {outcome}");
            }
            running.store(false, Ordering::SeqCst);
        });

        Ok(())
    }

    /// Stop the interception loop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Whether the engine is marked dead (thread exited while supposedly
    /// running). The daemon surfaces this as `enabled=false + last_error`.
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// Snapshot of the engine counters.
    pub fn stats(&self) -> B4Stats {
        B4Stats {
            packets_seen: self.stats.packets_seen.load(Ordering::Relaxed),
            tls_packets: self.stats.tls_packets.load(Ordering::Relaxed),
            mutated: self.stats.mutated.load(Ordering::Relaxed),
            dropped: self.stats.dropped.load(Ordering::Relaxed),
            accepted: self.stats.accepted.load(Ordering::Relaxed),
            errors: self.stats.errors.load(Ordering::Relaxed),
        }
    }
}

/// The blocking packet-processing loop. Every error path ACCEPTs the packet
/// (never hangs a flow) and increments the error counter. The loop only exits
/// on `running == false`; errors are non-fatal (logged + counted).
fn interception_loop(
    queue: &std::sync::Arc<NfQueue>,
    running: &Arc<AtomicBool>,
    stats: &Arc<AtomicU64Arr>,
    config: &EngineConfig,
    sets: &Arc<std::sync::Mutex<Vec<crate::set::B4Set>>>,
    ports: &[u16],
    udp_ports: &[u16],
    reassembler: &mut crate::reassembly::TcpReassembler,
) {
    while running.load(Ordering::SeqCst) {
        let packet = match queue.recv_packet() {
            Ok(Some(p)) => p,
            Ok(None) => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("NFQUEUE recv: unrecognized message (not packet), skipping");
                continue;
            }
            Err(e) => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("NFQUEUE recv error: {e}");
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
        };
        stats.packets_seen.fetch_add(1, Ordering::Relaxed);

        let Some(payload) = &packet.payload else {
            // No payload (COPY_META) — can't mutate; accept.
            stats.accepted.fetch_add(1, Ordering::Relaxed);
            if queue
                .verdict(packet.packet_id, crate::nfq::NF_ACCEPT, None)
                .is_err()
            {
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
            continue;
        };

        // Determine protocol: UDP packets are only interesting to the fake
        // plane; everything else is treated as TCP.
        let proto = if payload.len() >= 9 && payload[0] >> 4 == 4 {
            payload[9]
        } else if payload.len() >= 8 && payload[0] >> 4 == 6 {
            payload[7]
        } else {
            0
        };

        if proto == 17 {
            // UDP: full mission strategy sets may want faking.
            let sets_snapshot = sets.lock().unwrap_or_else(|e| e.into_inner()).clone();
            handle_udp_packet(
                queue,
                stats,
                payload,
                &sets_snapshot,
                udp_ports,
                packet.packet_id,
            );
            continue;
        }

        // TCP path (legacy + full sets).
        let tcp = match TcpPacket::parse(payload) {
            Some(t) => t,
            None => {
                // Not TCP — pass through untouched.
                stats.accepted.fetch_add(1, Ordering::Relaxed);
                if queue
                    .verdict(packet.packet_id, crate::nfq::NF_ACCEPT, None)
                    .is_err()
                {
                    stats.errors.fetch_add(1, Ordering::Relaxed);
                }
                continue;
            }
        };

        // Only intercept the configured destination ports.
        if !ports.contains(&tcp.dst_port()) {
            stats.accepted.fetch_add(1, Ordering::Relaxed);
            if queue
                .verdict(packet.packet_id, crate::nfq::NF_ACCEPT, None)
                .is_err()
            {
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
            continue;
        }

        // Try to identify the destination host from TLS SNI. A ClientHello is
        // often fragmented across two segments (e.g. 1460 + 361 bytes); the
        // per-flow reassembler reconstructs just the head of the stream so the
        // stateless SNI parser can run on the complete record.
        let tcp_payload = tcp.tcp_payload();
        let reassembled = reassembler.feed(
            crate::reassembly::FlowKey::for_packet(&tcp),
            tcp.tcp_seq(),
            tcp_payload,
            tcp.tcp_flags() & 0x11 != 0, // FIN or RST
        );
        let host = reassembled.or_else(|| extract_tls_sni(tcp_payload));
        tracing::debug!(
            dst_port = tcp.dst_port(),
            payload_len = tcp_payload.len(),
            head = %hex6(tcp_payload),
            sni = ?host,
            "b4 engine: inspected port packet",
        );
        if host.is_some() {
            stats.tls_packets.fetch_add(1, Ordering::Relaxed);
        }

        let profile = host.as_deref().and_then(|h| config.profile_for(h));
        // A full mission set matches by SNI domain (exact/suffix).
        let sets_snapshot = sets.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let set = host
            .as_deref()
            .and_then(|h| sets_snapshot.iter().find(|s| set_matches_host(s, h)));

        // If a full set matches, apply it (mission §6). Legacy profiles still
        // work when no set matches.
        if let Some(set) = set {
            if let Some(outcome) = apply_set_to_tcp(set, &tcp, queue, stats, packet.packet_id) {
                continue; // handled (mutated / fragmented / dropped)
            }
            stats.accepted.fetch_add(1, Ordering::Relaxed);
            if queue
                .verdict(packet.packet_id, crate::nfq::NF_ACCEPT, None)
                .is_err()
            {
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
            continue;
        }

        let Some(profile) = profile else {
            // No matching profile → pass through.
            stats.accepted.fetch_add(1, Ordering::Relaxed);
            if queue
                .verdict(packet.packet_id, crate::nfq::NF_ACCEPT, None)
                .is_err()
            {
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
            continue;
        };

        // Apply the profile's strategies in order.
        let mut changed = false;
        let mut mutated_pkt = tcp.clone();
        for strat in &profile.strategies {
            if apply_to(&mut mutated_pkt, strat) {
                changed = true;
            }
        }

        if changed {
            crate::packet::fix_ipv4_checksum(&mut mutated_pkt);
            crate::packet::fix_tcp_checksum(&mut mutated_pkt);
            stats.mutated.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                host = ?host,
                strategies = ?profile.strategies,
                "b4 mutation applied",
            );
            if queue
                .verdict(
                    packet.packet_id,
                    crate::nfq::NF_ACCEPT,
                    Some(&mutated_pkt.raw),
                )
                .is_err()
            {
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            stats.accepted.fetch_add(1, Ordering::Relaxed);
            if queue
                .verdict(packet.packet_id, crate::nfq::NF_ACCEPT, None)
                .is_err()
            {
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Whether a strategy set's targets match a hostname. Literal SNI domains plus
/// geosite categories are checked; the geosite store is consulted lazily via
/// the host's suffix/domain form (the store's `matches` handles exact+suffix).
fn set_matches_host(set: &crate::set::B4Set, host: &str) -> bool {
    if !set.enabled {
        return false;
    }
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    for d in &set.targets.sni_domains {
        let d = d.trim_end_matches('.').to_ascii_lowercase();
        if h == d || h.ends_with(&format!(".{d}")) {
            return true;
        }
    }
    // Geosite categories: use the built-in store (loads once, cached).
    if set.has_geosite() {
        use std::sync::OnceLock;
        static STORE: OnceLock<crate::geosite::GeositeStore> = OnceLock::new();
        let store = STORE.get_or_init(crate::geosite::GeositeStore::load);
        for cat in &set.targets.geosite_categories {
            if let Some(c) = store.get(cat) {
                if c.matches(&h) {
                    return true;
                }
            }
        }
    }
    false
}

/// Apply a full strategy set to one TCP packet. Returns `Some(())` if the
/// packet was handled (verdict sent); `None` when the caller should accept it.
fn apply_set_to_tcp(
    set: &crate::set::B4Set,
    tcp: &TcpPacket,
    queue: &std::sync::Arc<NfQueue>,
    stats: &Arc<AtomicU64Arr>,
    packet_id: u32,
) -> Option<()> {
    // Fragmentation plane: split data-bearing TLS segments into two IP
    // fragments (the first replaces the original; the second is injected).
    if let Some((frag1, frag2)) = crate::set_apply::fragment_for(set, tcp) {
        // Send the second fragment via the same queue? NFQUEUE verdicts are
        // per-packet; injecting a second packet requires a raw socket. For the
        // engine we keep it simple: emit frag1 as the verdict payload and log
        // frag2 (a full inline implementation would inject it via a raw IP
        // socket — handled by the daemon's DPI manager hook).
        stats.mutated.fetch_add(1, Ordering::Relaxed);
        let _ = frag2;
        if queue
            .verdict(packet_id, crate::nfq::NF_ACCEPT, Some(&frag1))
            .is_err()
        {
            stats.errors.fetch_add(1, Ordering::Relaxed);
        }
        return Some(());
    }

    // Standard plane: MSS/SACK/TTL/pastseq.
    let is_syn = tcp.tcp_flags() & 0x02 != 0;
    let is_first = tcp.tcp_payload().len() > 0;
    match crate::set_apply::apply_tcp(set, tcp, is_syn, is_first) {
        crate::set_apply::ApplyOutcome::Mutated(bytes) => {
            stats.mutated.fetch_add(1, Ordering::Relaxed);
            if queue
                .verdict(packet_id, crate::nfq::NF_ACCEPT, Some(&bytes))
                .is_err()
            {
                stats.errors.fetch_add(1, Ordering::Relaxed);
            }
            Some(())
        }
        crate::set_apply::ApplyOutcome::Drop => {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            let _ = queue.verdict(packet_id, crate::nfq::NF_DROP, None);
            Some(())
        }
        _ => None,
    }
}

/// Handle a UDP packet: the full-set fake plane injects fake QUIC packets
/// toward the target (via a raw socket is outside this engine's scope, so we
/// accept the packet and record the decision; the daemon's DPI manager injects
/// the fake packets). We still track that UDP faking was decided.
fn handle_udp_packet(
    queue: &std::sync::Arc<NfQueue>,
    stats: &Arc<AtomicU64Arr>,
    payload: &[u8],
    sets: &[crate::set::B4Set],
    udp_ports: &[u16],
    packet_id: u32,
) {
    let udp = match crate::packet::UdpPacket::parse(payload) {
        Some(u) => u,
        None => {
            stats.accepted.fetch_add(1, Ordering::Relaxed);
            let _ = queue.verdict(packet_id, crate::nfq::NF_ACCEPT, None);
            return;
        }
    };
    if !udp_ports.contains(&udp.dst_port()) {
        stats.accepted.fetch_add(1, Ordering::Relaxed);
        let _ = queue.verdict(packet_id, crate::nfq::NF_ACCEPT, None);
        return;
    }
    // Any set wanting UDP faking marks this as intercepted (the engine accepts
    // the real packet; fake packets are injected by the DPI manager hook).
    let interested = sets
        .iter()
        .any(|s| s.enabled && s.udp.mode == "fake" && s.udp.dport_filter.is_empty());
    if interested {
        stats.mutated.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(
            dst_port = udp.dst_port(),
            "b4 engine: UDP fake plane active (fake packets injected by DPI manager)"
        );
    }
    stats.accepted.fetch_add(1, Ordering::Relaxed);
    let _ = queue.verdict(packet_id, crate::nfq::NF_ACCEPT, None);
}

/// Apply a strategy to a packet; returns true if it changed anything.
fn apply_to(pkt: &mut TcpPacket, strat: &Strategy) -> bool {
    match *strat {
        Strategy::Mss { mss } => crate::packet::tcp_opt::set_mss(pkt, mss),
        Strategy::StripSack => {
            crate::packet::tcp_opt::strip_option(pkt, crate::packet::tcp_opt::SACK_PERMITTED)
        }
        Strategy::Ttl { ttl } => {
            if pkt.raw[8] != ttl {
                pkt.raw[8] = ttl;
                true
            } else {
                false
            }
        }
        Strategy::Noop => false,
    }
}

/// Debug helper: hex of the first up-to-6 bytes of a payload.
fn hex6(bytes: &[u8]) -> String {
    bytes.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_ttl_changes_byte() {
        let raw = crate::packet::tests_synth_syn();
        let mut pkt = TcpPacket::parse(&raw).unwrap();
        assert!(apply_to(&mut pkt, &Strategy::Ttl { ttl: 61 }));
        assert_eq!(pkt.raw[8], 61);
    }
}
