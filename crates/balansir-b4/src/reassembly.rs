//! Per-connection TCP reassembly for the DPI-bypass engine.
//!
//! A TLS ClientHello is commonly larger than a single segment (e.g. 1821 bytes
//! split as 1460 + 361). The engine's `extract_tls_sni` is stateless and only
//! works on a full record, so a fragmented ClientHello was never recognized.
//! This module reassembles the byte stream of each flow *just enough* to reach
//! a complete TLS handshake record, then the existing parser runs on the
//! reassembled buffer.
//!
//! It is deliberately bounded: only the first (up to `max_bytes`) bytes of a
//! flow are buffered, streams that do not begin with a TLS handshake record
//! are ignored, and stale flows are evicted. No user data beyond the
//! ClientHello window is retained.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// A flow's connection tuple (the key of the reassembly state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FlowKey {
    /// Build a flow key from a parsed TCP packet.
    pub fn for_packet(pkt: &crate::packet::TcpPacket) -> Self {
        Self {
            src_ip: Ipv4Addr::from(pkt.src_ip()),
            dst_ip: Ipv4Addr::from(pkt.dst_ip()),
            src_port: pkt.src_port(),
            dst_port: pkt.dst_port(),
        }
    }
}

/// In-flight reassembly state for a single flow.
struct Flow {
    /// Sequence number of the first byte in `buffer` (absolute TCP seq).
    base_seq: u32,
    /// The reassembled stream built so far (starts at the flow's first byte).
    buffer: Vec<u8>,
    /// Whether we have already found an SNI; when set the stream is retired
    /// (mutations key off the profile, not the reassembler).
    decided: Option<String>,
    /// Last activity; used for eviction of idle flows.
    last_seen: Instant,
}

impl Flow {
    fn new(base_seq: u32, now: Instant) -> Self {
        Self {
            base_seq,
            buffer: Vec::with_capacity(2048),
            decided: None,
            last_seen: now,
        }
    }
}

/// Reassembles the beginning of TCP streams to expose a full TLS ClientHello.
pub struct TcpReassembler {
    flows: HashMap<FlowKey, Flow>,
    /// Maximum bytes buffered per flow (a ClientHello is ~1.5-4 KiB; 16 KiB is
    /// generous headroom and still tiny per flow).
    max_bytes: usize,
    /// Maximum number of concurrently tracked flows; oldest-seen are evicted.
    max_flows: usize,
    /// Idle timeout after which a flow is dropped.
    idle_timeout: Duration,
    /// Packets processed since the last periodic eviction pass.
    since_evict: u64,
    /// How often (in packets) to run a cheap eviction sweep.
    evict_every: u64,
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self {
            flows: HashMap::new(),
            max_bytes: 16 * 1024,
            max_flows: 4096,
            idle_timeout: Duration::from_secs(30),
            since_evict: 0,
            evict_every: 256,
        }
    }
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle one TCP segment. `tcp_seq` is the sequence number of the first
    /// byte of `payload`. Returns the flow's SNI once the stream has been
    /// reassembled far enough (None until then).
    ///
    /// Never fails the flow: on any anomaly (oversize, gap, non-TLS start) the
    /// flow is dropped from tracking and `None` returned — the packet itself
    /// is always safe to pass through.
    pub fn feed(
        &mut self,
        key: FlowKey,
        tcp_seq: u32,
        payload: &[u8],
        fin_rst: bool,
    ) -> Option<String> {
        self.since_evict += 1;
        if self.since_evict.is_multiple_of(self.evict_every) {
            self.evict_expired();
        }

        if payload.is_empty() {
            return None;
        }
        // Terminal flags close the stream; nothing more to reassemble.
        if fin_rst {
            self.flows.remove(&key);
            return None;
        }

        // Ensure a flow exists (creating one if this is the first segment),
        // enforcing the global flow-count bound before growth.
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= self.max_flows {
                self.evict_expired();
                if self.flows.len() >= self.max_flows {
                    // Still full: drop the incoming flow rather than
                    // unboundedly growing.
                    return None;
                }
            }
            self.flows
                .insert(key, Flow::new(tcp_seq, Instant::now()));
        }

        // Process the segment. Deferred removal: any `drop_flow` decision is
        // applied after the mutable borrow of the flow is released, so we
        // never call `self.flows.remove` while `flow` is alive.
        let max_bytes = self.max_bytes;
        let (result, drop_flow) = (|| {
            let flow = self.flows.get_mut(&key).unwrap();
            flow.last_seen = Instant::now();

            if let Some(decided) = &flow.decided {
                // Stream already classified; nothing more to buffer.
                return (Some(decided.clone()), false);
            }

            let drop_flow = false;
            if flow.buffer.is_empty() {
                // First byte decides whether this is a TLS handshake record at all.
                if payload[0] != 0x16 {
                    // Not a ClientHello start — never reassemble this flow.
                    return (None, true);
                }
                flow.buffer.extend_from_slice(payload);
            } else {
                // Append at the expected offset. Out-of-order and duplicate
                // segments are the only reasons `tcp_seq` could diverge from the
                // expected next seq; we only support in-order reassembly of the
                // head of the stream, so any gap means we can't reconstruct the
                // record safely → stop tracking (the packet still passes).
                let expected_seq = flow.base_seq.wrapping_add(flow.buffer.len() as u32);
                if tcp_seq != expected_seq {
                    if tcp_seq < expected_seq
                        && tcp_seq.wrapping_add(payload.len() as u32) > expected_seq
                    {
                        // Overlapping (retransmit + new data): append the tail
                        // that is genuinely new.
                        let covered = expected_seq - tcp_seq;
                        let new_tail = &payload[covered as usize..];
                        let room = max_bytes.saturating_sub(flow.buffer.len());
                        if new_tail.len() > room {
                            return (None, true);
                        }
                        flow.buffer.extend_from_slice(new_tail);
                    } else if tcp_seq < expected_seq {
                        // Pure duplicate of already-buffered bytes: the buffer
                        // was already evaluated when those bytes were added; a
                        // duplicate changes nothing.
                        return (flow.decided.clone(), false);
                    } else {
                        // Gap → cannot reassemble; drop the flow.
                        return (None, true);
                    }
                } else {
                    let room = max_bytes.saturating_sub(flow.buffer.len());
                    if payload.len() > room {
                        return (None, true);
                    }
                    flow.buffer.extend_from_slice(payload);
                }
            }

            if flow.buffer.len() > max_bytes {
                return (None, true);
            }

            // Extract the buffered bytes so we can release the flow borrow
            // before deciding (and potentially retiring) the flow.
            let snapshot = std::mem::take(&mut flow.buffer);
            let decided = crate::packet::extract_tls_sni(&snapshot);
            if let Some(host) = decided {
                // Stream classified: retire it (SNI is all we need). Keep the
                // decided host so later segments short-circuit.
                flow.decided = Some(host.clone());
            } else {
                // Not yet complete: put the bytes back for the next segment.
                flow.buffer = snapshot;
            }
            (flow.decided.clone(), drop_flow)
        })();

        if drop_flow {
            self.flows.remove(&key);
        }
        result
    }

    /// Remove flows idle longer than `idle_timeout`.
    pub fn evict_expired(&mut self) {
        let cutoff = Instant::now() - self.idle_timeout;
        self.flows.retain(|_, f| f.last_seen >= cutoff);
    }

    /// Remove a specific flow (e.g. on FIN/RST or profile decision).
    pub fn drop_flow(&mut self, key: &FlowKey) {
        self.flows.remove(key);
    }

    /// Number of tracked flows (tests/diagnostics).
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello record that `extract_tls_sni` can parse.
    /// Handcrafted to contain a valid server_name extension. When `pad` is
    /// non-zero, a padding extension is appended so the record exceeds the
    /// `pad` size (used to simulate real fragmentation).
    fn client_hello_payload(sni: &str, pad: usize) -> Vec<u8> {
        // server_name extension payload: list_len(2) name_type(1) name_len(2) name
        let mut name_list = Vec::new();
        let name = sni.as_bytes();
        name_list.push(0x00); // name_type: host_name
        name_list.extend_from_slice(&(name.len() as u16).to_be_bytes());
        name_list.extend_from_slice(name);
        let mut ext_data = Vec::new();
        ext_data.extend_from_slice(&(name_list.len() as u16).to_be_bytes());
        ext_data.extend_from_slice(&name_list);

        // One server_name extension: type(2) length(2) payload.
        let mut ext_block = Vec::new();
        ext_block.extend_from_slice(&[0x00, 0x00]); // ext_type: server_name
        ext_block.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        ext_block.extend_from_slice(&ext_data);

        // Optional padding extension to force a >1460-byte ClientHello.
        if pad > 0 {
            let mut pad_block = Vec::new();
            pad_block.extend_from_slice(&[0x00, 0x15]); // ext_type: padding
            pad_block.extend_from_slice(&(pad as u16).to_be_bytes());
            pad_block.extend_from_slice(&vec![0u8; pad]);
            ext_block.extend_from_slice(&pad_block);
        }

        // ClientHello body assembled backwards so lengths are known.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&[0x00, 0x02]); // cipher suites length
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(1); // compression methods length
        body.push(0); // null
        body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_block);

        let mut hello = Vec::new();
        hello.push(0x01); // handshake type: ClientHello
        hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]); // 24-bit length
        hello.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // handshake record
        record.extend_from_slice(&[0x03, 0x03]); // version
        record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        record.extend_from_slice(&hello);
        record
    }

    fn key() -> FlowKey {
        FlowKey {
            src_ip: Ipv4Addr::new(192, 168, 3, 10),
            dst_ip: Ipv4Addr::new(93, 184, 216, 34),
            src_port: 45123,
            dst_port: 443,
        }
    }

    #[test]
    fn single_segment_hello_classified() {
        let mut r = TcpReassembler::new();
        let payload = client_hello_payload("example.com", 0);
        let sni = r.feed(key(), 0, &payload, false);
        assert_eq!(sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn fragmented_1460_plus_361_reassembled() {
        let mut r = TcpReassembler::new();
        // ~1500+ byte ClientHello so it must be split (real-world 1460 + rest).
        let payload = client_hello_payload("frag.example.net", 1400);
        assert!(payload.len() > 1460, "test needs a fragmentable hello");
        let (a, b) = payload.split_at(1460);

        assert_eq!(r.feed(key(), 0, a, false), None, "first fragment incomplete");
        assert_eq!(
            r.feed(key(), 1460, b, false),
            Some("frag.example.net".to_string()),
            "second fragment completes the record and yields SNI"
        );
    }

    #[test]
    fn out_of_order_first_fragment_is_not_classified() {
        let mut r = TcpReassembler::new();
        let payload = client_hello_payload("ooo.example.com", 1400);
        let (a, b) = payload.split_at(1460);
        // Second fragment arrives before the first: it does not start with a
        // TLS record marker, so it is never tracked (the record is
        // unrecoverable from a bare mid-stream segment).
        assert_eq!(r.feed(key(), 1460, b, false), None);
        // Once the first fragment arrives the stream assembles in order and
        // the retransmitted second fragment completes the record.
        assert_eq!(r.feed(key(), 0, a, false), None);
        assert_eq!(
            r.feed(key(), 1460, b, false),
            Some("ooo.example.com".to_string())
        );
    }

    #[test]
    fn duplicate_segment_ignored() {
        let mut r = TcpReassembler::new();
        let payload = client_hello_payload("dup.example.org", 0);
        assert_eq!(r.feed(key(), 0, &payload, false), Some("dup.example.org".to_string()));
        // Duplicate retransmission after decision: still classified.
        assert_eq!(r.feed(key(), 0, &payload, false), Some("dup.example.org".to_string()));
    }

    #[test]
    fn fin_rst_clears_flow() {
        let mut r = TcpReassembler::new();
        let payload = client_hello_payload("fin.example.com", 0);
        let sni = r.feed(key(), 0, &payload, false);
        assert_eq!(sni.as_deref(), Some("fin.example.com"));
        r.feed(key(), 100, &[1, 2, 3], true);
        assert!(r.is_empty());
    }

    #[test]
    fn non_tls_start_is_not_tracked() {
        let mut r = TcpReassembler::new();
        assert_eq!(r.feed(key(), 0, b"\x00\x00\x00\x01hello", false), None);
        assert!(r.is_empty(), "non-TLS flow must not be buffered");
    }

    #[test]
    fn idle_flows_are_evicted() {
        let mut r = TcpReassembler::new();
        r.idle_timeout = Duration::from_millis(1);
        let payload = client_hello_payload("evict.example.com", 0);
        r.feed(key(), 0, &payload[..1460.min(payload.len())], false);
        assert_eq!(r.len(), 1);
        std::thread::sleep(Duration::from_millis(5));
        r.evict_expired();
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn oversize_flow_is_dropped() {
        let mut r = TcpReassembler::new();
        r.max_bytes = 8;
        let payload = client_hello_payload("big.example.com", 0);
        assert_eq!(r.feed(key(), 0, &payload[..6], false), None);
        // Next fragment pushes beyond max_bytes → flow dropped.
        assert_eq!(r.feed(key(), 6, &payload[6..], false), None);
        assert!(r.is_empty());
    }
}
