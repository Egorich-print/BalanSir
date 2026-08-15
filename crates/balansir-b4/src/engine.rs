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
}

/// The DPI-bypass engine runtime.
pub struct B4Engine {
    queue_num: u16,
    config: EngineConfig,
    /// Which TCP destination ports to intercept (default 443).
    ports: Vec<u16>,
    running: Arc<AtomicBool>,
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
}

impl B4Engine {
    /// Create the engine (does not start the loop).
    pub fn new(queue_num: u16, config: EngineConfig, ports: Vec<u16>) -> Self {
        Self {
            queue_num,
            config,
            ports: if ports.is_empty() { vec![443] } else { ports },
            running: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(AtomicU64Arr::default()),
        }
    }

    /// Run the interception loop until stopped.
    pub async fn run(&self) -> Result<(), String> {
        let queue = NfQueue::new(self.queue_num, 64 * 1024)
            .map_err(|e| format!("NFQUEUE bind failed: {e}"))?;
        self.running.store(true, Ordering::SeqCst);
        tracing::info!(queue = self.queue_num, "b4 engine listening (NFQUEUE)",);

        // This is a blocking netlink loop; run it on a dedicated blocking
        // task so the async executor is not starved.
        let stats = Arc::clone(&self.stats);
        let running = Arc::clone(&self.running);
        let config = self.config.clone();
        let ports = self.ports.clone();
        let queue = std::sync::Arc::new(queue);

        tokio::task::spawn_blocking(move || {
            tracing::info!("b4 engine: interception thread started");
            while running.load(Ordering::SeqCst) {
                let packet = match queue.recv_packet() {
                    Ok(Some(p)) => p,
                    Ok(None) => {
                        tracing::warn!("NFQUEUE recv: unrecognized message (not packet), skipping");
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!("NFQUEUE recv error: {e}");
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                };
                stats.packets_seen.fetch_add(1, Ordering::Relaxed);

                let Some(payload) = &packet.payload else {
                    // No payload (COPY_META) — can't mutate; accept.
                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                    let _ = queue.verdict(packet.packet_id, crate::nfq::NF_ACCEPT, None);
                    continue;
                };

                let tcp = match TcpPacket::parse(payload) {
                    Some(t) => t,
                    None => {
                        // Not TCP — pass through untouched.
                        stats.accepted.fetch_add(1, Ordering::Relaxed);
                        let _ = queue.verdict(packet.packet_id, crate::nfq::NF_ACCEPT, None);
                        continue;
                    }
                };

                // Only intercept the configured destination ports.
                if !ports.contains(&tcp.dst_port()) {
                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                    let _ = queue.verdict(packet.packet_id, crate::nfq::NF_ACCEPT, None);
                    continue;
                }

                // Try to identify the destination host from TLS SNI.
                let tcp_payload = &payload[tcp.tcp_offset + tcp.tcp_header_len..];
                let host = extract_tls_sni(tcp_payload);
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
                let Some(profile) = profile else {
                    // No matching profile → pass through.
                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                    let _ = queue.verdict(packet.packet_id, crate::nfq::NF_ACCEPT, None);
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
                    let _ = queue.verdict(
                        packet.packet_id,
                        crate::nfq::NF_ACCEPT,
                        Some(&mutated_pkt.raw),
                    );
                } else {
                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                    let _ = queue.verdict(packet.packet_id, crate::nfq::NF_ACCEPT, None);
                }
            }
        });

        Ok(())
    }

    /// Stop the interception loop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Snapshot of the engine counters.
    pub fn stats(&self) -> B4Stats {
        B4Stats {
            packets_seen: self.stats.packets_seen.load(Ordering::Relaxed),
            tls_packets: self.stats.tls_packets.load(Ordering::Relaxed),
            mutated: self.stats.mutated.load(Ordering::Relaxed),
            dropped: self.stats.dropped.load(Ordering::Relaxed),
            accepted: self.stats.accepted.load(Ordering::Relaxed),
        }
    }
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

/// Default engine config helper (for tests and sane defaults).
pub fn default_config() -> EngineConfig {
    use crate::strategies::Profile;
    EngineConfig {
        profiles: vec![Profile {
            name: "default".into(),
            domains: vec![],
            strategies: vec![Strategy::Mss { mss: 1200 }],
        }],
    }
}

/// Debug helper: hex of the first up-to-6 bytes of a payload.
fn hex6(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
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

    #[test]
    fn default_config_resolves_default() {
        let cfg = default_config();
        assert!(cfg.profile_for("anyhost.example").is_some());
    }
}
