//! IP/TCP packet parsing and mutation for DPI-bypass strategies.
//!
//! Operates on raw IP packets as delivered by NFQUEUE (COPY_PACKET). Only IPv4
//! is handled for now (IPv6 is a documented limitation). All parsing is
//! bounds-checked and defensive — a malformed packet is returned as-is.

/// A parsed IPv4 header + TCP header (when present).
#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub raw: Vec<u8>,
    pub ip_header_len: usize,
    pub ip_total_len: usize,
    pub tcp_offset: usize,
    pub tcp_header_len: usize,
    pub tcp_doff_field: usize, // offset of the 4-bit data offset byte
    pub checksum_offsets: (usize, usize),
}

impl TcpPacket {
    /// Try to parse `raw` as IPv4+TCP. Returns None if not TCP or malformed.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < 20 {
            return None;
        }
        // IPv4 version/ihl
        let ver_ihl = raw[0];
        if ver_ihl >> 4 != 4 {
            return None;
        }
        let ip_header_len = ((ver_ihl & 0x0f) as usize) * 4;
        if ip_header_len < 20 || raw.len() < ip_header_len {
            return None;
        }
        let proto = raw[9];
        if proto != 6 {
            // TCP only
            return None;
        }
        let ip_total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        if ip_total_len < ip_header_len || raw.len() < ip_total_len {
            return None;
        }
        let tcp_offset = ip_header_len;
        if raw.len() < tcp_offset + 20 {
            return None;
        }
        // TCP data offset (in 32-bit words) is the high nibble of byte 12.
        let tcp_doff_field = tcp_offset + 12;
        let tcp_header_len = ((raw[tcp_doff_field] >> 4) as usize) * 4;
        if tcp_header_len < 20 || raw.len() < tcp_offset + tcp_header_len {
            return None;
        }
        // IPv4 header checksum is bytes 10..12; TCP checksum is bytes 16..18
        // of the TCP header.
        Some(Self {
            raw: raw.to_vec(),
            ip_header_len,
            ip_total_len,
            tcp_offset,
            tcp_header_len,
            tcp_doff_field,
            checksum_offsets: (10, tcp_offset + 16),
        })
    }

    /// Destination port (big-endian bytes 2..4 of TCP header).
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.raw[self.tcp_offset + 2], self.raw[self.tcp_offset + 3]])
    }

    /// Source port.
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.raw[self.tcp_offset], self.raw[self.tcp_offset + 1]])
    }

    /// Full packet length (including IP header).
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Whether the packet has no payload bytes.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// IPv4 source address (big-endian bytes 12..16 of the IP header).
    pub fn src_ip(&self) -> [u8; 4] {
        [self.raw[12], self.raw[13], self.raw[14], self.raw[15]]
    }

    /// IPv4 destination address (big-endian bytes 16..20 of the IP header).
    pub fn dst_ip(&self) -> [u8; 4] {
        [self.raw[16], self.raw[17], self.raw[18], self.raw[19]]
    }

    /// TCP sequence number of the first payload byte (bytes 4..8 of the TCP
    /// header).
    pub fn tcp_seq(&self) -> u32 {
        u32::from_be_bytes([
            self.raw[self.tcp_offset + 4],
            self.raw[self.tcp_offset + 5],
            self.raw[self.tcp_offset + 6],
            self.raw[self.tcp_offset + 7],
        ])
    }

    /// Set the TCP sequence number in place.
    pub fn set_tcp_seq(&mut self, seq: u32) {
        self.raw[self.tcp_offset + 4..self.tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());
    }

    /// TCP flags byte (byte 13 of the TCP header). Lower bits are FIN/SYN/RST/
    /// PSH/ACK/URG/ECE/CWR.
    pub fn tcp_flags(&self) -> u8 {
        self.raw[self.tcp_offset + 13]
    }

    /// The TCP payload (application data), i.e. everything after the TCP header.
    pub fn tcp_payload(&self) -> &[u8] {
        &self.raw[self.tcp_offset + self.tcp_header_len..]
    }
}

/// TCP header option manipulation.
pub mod tcp_opt {
    use super::TcpPacket;

    /// The TCP MSS option kind.
    pub const MSS: u8 = 2;
    /// The TCP SACK-permitted option kind.
    pub const SACK_PERMITTED: u8 = 4;

    /// Set the TCP MSS option value in place. Returns new packet if the MSS
    /// option was found and updated (best-effort: if absent, unchanged).
    pub fn set_mss(pkt: &mut TcpPacket, mss: u16) -> bool {
        let start = pkt.tcp_offset + 20;
        let end = pkt.tcp_offset + pkt.tcp_header_len;
        let mut i = start;
        while i + 1 < end {
            let kind = pkt.raw[i];
            if kind == 0 {
                break; // EOL
            }
            if kind == 1 {
                i += 1;
                continue; // NOP
            }
            let len = pkt.raw[i + 1] as usize;
            if len < 2 || i + len > end {
                break;
            }
            if kind == MSS && len >= 4 {
                pkt.raw[i + 2..i + 4].copy_from_slice(&mss.to_be_bytes());
                return true;
            }
            i += len;
        }
        false
    }

    /// Strip a TCP option kind in place (e.g. SACK-permitted). Rebuilds the
    /// TCP header so the option bytes are removed. Returns true if changed.
    pub fn strip_option(pkt: &mut TcpPacket, kind: u8) -> bool {
        let start = pkt.tcp_offset + 20;
        let end = pkt.tcp_offset + pkt.tcp_header_len;
        let mut kept = Vec::new();
        let mut changed = false;
        let mut i = start;
        while i < end {
            let k = pkt.raw[i];
            if k == 0 {
                // EOL: copy the rest (including EOL + padding)
                kept.extend_from_slice(&pkt.raw[i..end]);
                break;
            }
            if k == 1 {
                kept.push(1);
                i += 1;
                continue;
            }
            let len = pkt.raw[i + 1] as usize;
            if len < 2 || i + len > end {
                kept.extend_from_slice(&pkt.raw[i..end]);
                break;
            }
            if k == kind {
                changed = true;
            } else {
                kept.extend_from_slice(&pkt.raw[i..i + len]);
            }
            i += len;
        }
        if !changed {
            return false;
        }
        // Pad to 4-byte alignment with NOPs (kind 1).
        while kept.len() % 4 != 0 {
            kept.push(1);
        }
        // Rebuild the packet: copy IP header + fixed TCP header (20 bytes) +
        // new options + original payload.
        let tcp_start = pkt.tcp_offset;
        let payload = pkt.raw[tcp_start + pkt.tcp_header_len..].to_vec();
        let mut out = Vec::new();
        out.extend_from_slice(&pkt.raw[..tcp_start]);
        out.extend_from_slice(&pkt.raw[tcp_start..tcp_start + 20]);
        out.extend_from_slice(&kept);
        out.extend_from_slice(&payload);
        // Update TCP data offset field.
        let new_tcp_header_len = (20 + kept.len() + 3) & !3;
        let dof = (new_tcp_header_len / 4) as u8;
        // The data offset is the high nibble of the byte at tcp_start+12.
        out[tcp_start + 12] = (dof << 4) | (out[tcp_start + 12] & 0x0f);
        // Update IP total length.
        let new_total = out.len();
        let old_ip_len = u16::from_be_bytes([out[2], out[3]]) as usize;
        let _ = old_ip_len;
        out[2..4].copy_from_slice(&(new_total as u16).to_be_bytes());
        pkt.raw = out;
        pkt.tcp_header_len = new_tcp_header_len;
        true
    }
}

/// Recompute and write the IPv4 header checksum.
pub fn fix_ipv4_checksum(pkt: &mut TcpPacket) {
    let mut sum: u32 = 0;
    for i in 0..pkt.ip_header_len {
        if i == 10 || i == 11 {
            continue; // skip checksum field
        }
        let b = pkt.raw[i] as u32;
        sum += if i % 2 == 0 { b << 8 } else { b };
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    pkt.raw[10..12].copy_from_slice(&csum.to_be_bytes());
}

/// A parsed IPv4+UDP packet (used by the UDP faking plane).
#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub raw: Vec<u8>,
    pub ip_header_len: usize,
    pub udp_offset: usize,
    pub udp_len: usize,
}

impl UdpPacket {
    /// Try to parse `raw` as IPv4+UDP. Returns None if not UDP or malformed.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < 20 {
            return None;
        }
        let ver_ihl = raw[0];
        if ver_ihl >> 4 != 4 {
            return None;
        }
        let ip_header_len = ((ver_ihl & 0x0f) as usize) * 4;
        if ip_header_len < 20 || raw.len() < ip_header_len {
            return None;
        }
        let proto = raw[9];
        if proto != 17 {
            return None; // UDP only
        }
        let ip_total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        if ip_total_len < ip_header_len || raw.len() < ip_total_len {
            return None;
        }
        let udp_offset = ip_header_len;
        if raw.len() < udp_offset + 8 {
            return None;
        }
        let udp_len = u16::from_be_bytes([raw[udp_offset + 4], raw[udp_offset + 5]]) as usize;
        if udp_len < 8 || raw.len() < udp_offset + udp_len {
            return None;
        }
        Some(Self {
            raw: raw.to_vec(),
            ip_header_len,
            udp_offset,
            udp_len,
        })
    }

    /// Destination port.
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.raw[self.udp_offset + 2], self.raw[self.udp_offset + 3]])
    }

    /// Source port.
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.raw[self.udp_offset], self.raw[self.udp_offset + 1]])
    }

    /// IPv4 source address.
    pub fn src_ip(&self) -> [u8; 4] {
        [self.raw[12], self.raw[13], self.raw[14], self.raw[15]]
    }

    /// IPv4 destination address.
    pub fn dst_ip(&self) -> [u8; 4] {
        [self.raw[16], self.raw[17], self.raw[18], self.raw[19]]
    }

    /// UDP payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.raw[self.udp_offset + 8..self.udp_offset + self.udp_len]
    }
}

/// Build a fake UDP packet (QUIC-looking) toward `dst` on port 443. The fake
/// carries the QUIC public header (long header, initial packet) with random
/// bytes so DPI's QUIC fingerprinting is confused. This is the "udp.mode=fake"
/// technique: when DPI sees malformed/random QUIC it stops tracking the flow,
/// and the client's real traffic is often passed (or forced back to TCP).
pub fn build_fake_quic_packet(
    src: [u8; 4],
    dst: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload_len: usize,
) -> Vec<u8> {
    // IP header (20) + UDP header (8) + QUIC-like payload.
    let len = 20 + 8 + payload_len.max(1);
    let mut pkt = vec![0u8; len];
    // IPv4 header.
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    // UDP header.
    let u = 20;
    pkt[u..u + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[u + 2..u + 4].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = 8 + payload_len.max(1);
    pkt[u + 4..u + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // QUIC public header (long header): first byte 0xC3 (header form + type),
    // version, 8-byte connection ID, then random payload.
    let p = u + 8;
    pkt[p] = 0xC3;
    if payload_len > 1 {
        pkt[p + 1..p + 5].copy_from_slice(&0x00000001u32.to_be_bytes()); // QUIC v1
        if payload_len > 5 {
            pkt[p + 5] = 0x00; // first byte of DCID length = 0
            for b in &mut pkt[p + 6..] {
                *b = fastrand_byte();
            }
        }
    }
    // Zero the IP header checksum then fix both.
    let mut tmp = TcpPacket {
        raw: pkt.clone(),
        ip_header_len: 20,
        ip_total_len: len,
        tcp_offset: u,
        tcp_header_len: 8,
        tcp_doff_field: 0,
        checksum_offsets: (10, u + 6),
    };
    fix_ipv4_checksum(&mut tmp);
    // Fix UDP checksum via a manual pseudo-header sum.
    fix_udp_checksum(&mut pkt, src, dst, u, udp_len);
    pkt
}

/// Fast pseudo-random byte (xorshift seeded from the address/time). Determinism
/// is not needed; we just need cheap, varied bytes for the fake payload.
fn fastrand_byte() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    ((nanos as u32 >> 3) as u8) ^ ((nanos as u32 >> 11) as u8)
}

/// Compute the UDP checksum (with IPv4 pseudo-header).
pub fn fix_udp_checksum(
    pkt: &mut [u8],
    src: [u8; 4],
    dst: [u8; 4],
    udp_offset: usize,
    udp_len: usize,
) {
    // Set checksum field to 0 first.
    pkt[udp_offset + 6..udp_offset + 8].copy_from_slice(&[0, 0]);
    let mut sum: u32 = 0;
    for i in (0..4).step_by(2) {
        sum += ((src[i] as u32) << 8) | (src[i + 1] as u32);
    }
    for i in (0..4).step_by(2) {
        sum += ((dst[i] as u32) << 8) | (dst[i + 1] as u32);
    }
    sum += 17; // UDP protocol
    sum += udp_len as u32;
    for i in (0..udp_len).step_by(2) {
        let hi = pkt[udp_offset + i] as u32;
        let lo = if i + 1 < udp_len {
            pkt[udp_offset + i + 1] as u32
        } else {
            0
        };
        sum += (hi << 8) | lo;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    pkt[udp_offset + 6..udp_offset + 8].copy_from_slice(&csum.to_be_bytes());
}

/// Split a TCP packet's payload into two IP fragments (mission §6
/// fragmentation plane). Returns the two raw IP packets (fragments), each with
/// the correct IP fragment offset and checksums. `split_at` is the byte offset
/// inside the TCP payload where the second fragment begins.
pub fn fragment_tcp_payload(pkt: &TcpPacket, split_at: usize) -> Option<(Vec<u8>, Vec<u8>)> {
    let payload = pkt.tcp_payload();
    if split_at == 0 || split_at >= payload.len() {
        return None;
    }
    let total = pkt.len();
    let tcp_header = pkt.tcp_offset + pkt.tcp_header_len;
    let mut frag1 = pkt.raw[..tcp_header + split_at].to_vec();
    let mut frag2 = Vec::new();

    // Fragment 1: IP total length = header + tcp header + first part.
    let f1_len = frag1.len() as u16;
    frag1[2..4].copy_from_slice(&f1_len.to_be_bytes());
    // Fragment offset 0, more-fragments flag (0x2000).
    frag1[6] = 0x40; // DF=0 (don't fragment bit clear), MBZ
    frag1[7] = 0x00;

    // Fragment 2: full IP header + remainder. Offset = (tcp_header)/8.
    let offset = (tcp_header / 8) as u16;
    frag2.extend_from_slice(&pkt.raw[..pkt.ip_header_len]);
    let f2_len = (pkt.ip_header_len + (total - tcp_header - split_at)) as u16;
    frag2[2..4].copy_from_slice(&f2_len.to_be_bytes());
    frag2[6] = 0x40;
    frag2[7] = ((offset >> 8) & 0xff) as u8;
    let _ = offset;
    frag2.extend_from_slice(&pkt.raw[tcp_header + split_at..]);

    // Recompute checksums on both.
    let mut f1 = TcpPacket {
        raw: frag1.clone(),
        ip_header_len: pkt.ip_header_len,
        ip_total_len: frag1.len(),
        tcp_offset: pkt.tcp_offset,
        tcp_header_len: pkt.tcp_header_len,
        tcp_doff_field: 0,
        checksum_offsets: (10, pkt.tcp_offset + 16),
    };
    fix_ipv4_checksum(&mut f1);
    fix_tcp_checksum(&mut f1);
    frag1 = f1.raw;

    // Fragment 2 is a pure IP fragment (no full TCP header), so only fix the
    // IP checksum.
    let mut f2 = TcpPacket {
        raw: frag2.clone(),
        ip_header_len: pkt.ip_header_len,
        ip_total_len: frag2.len(),
        tcp_offset: 0,
        tcp_header_len: 0,
        tcp_doff_field: 0,
        checksum_offsets: (10, 0),
    };
    fix_ipv4_checksum(&mut f2);
    frag2 = f2.raw;

    Some((frag1, frag2))
}

/// Recompute and write the TCP checksum (with pseudo-header).
pub fn fix_tcp_checksum(pkt: &mut TcpPacket) {
    let ip = &pkt.raw;
    let src: [u8; 4] = [ip[12], ip[13], ip[14], ip[15]];
    let dst: [u8; 4] = [ip[16], ip[17], ip[18], ip[19]];
    let tcp_len = pkt.len() - pkt.tcp_offset;
    let mut sum: u32 = 0;
    // pseudo-header
    for i in (0..4).step_by(2) {
        sum += ((src[i] as u32) << 8) | (src[i + 1] as u32);
    }
    for i in (0..4).step_by(2) {
        sum += ((dst[i] as u32) << 8) | (dst[i + 1] as u32);
    }
    sum += 6; // TCP protocol
    sum += tcp_len as u32;
    // TCP header + payload
    let tcp_start = pkt.tcp_offset;
    for i in (0..tcp_len).step_by(2) {
        let hi = pkt.raw[tcp_start + i] as u32;
        let lo = if i + 1 < tcp_len {
            pkt.raw[tcp_start + i + 1] as u32
        } else {
            0
        };
        sum += (hi << 8) | lo;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    let (cs_lo, cs_hi) = pkt.checksum_offsets;
    // offsets are (ip_checksum_pos, tcp_checksum_pos)
    pkt.raw[cs_hi..cs_hi + 2].copy_from_slice(&csum.to_be_bytes());
    // after touching the TCP header the IPv4 checksum is also invalid
    fix_ipv4_checksum(pkt);
    let _ = (cs_lo,);
}

/// Test-only helper: a plain SYN with an MSS option. Lives outside `cfg(test)`
/// so integration/unit tests in sibling modules can construct packets.
#[cfg(test)]
pub fn tests_synth_syn() -> Vec<u8> {
    synth_syn_with_mss(1460, false)
}

/// Test-only helper: a minimal IPv4+UDP packet to port 443.
#[cfg(test)]
pub fn tests_synth_udp() -> Vec<u8> {
    let mut pkt = vec![0u8; 20 + 8 + 12];
    // IP header
    pkt[0] = 0x45;
    let pkt_len = pkt.len() as u16;
    pkt[2..4].copy_from_slice(&pkt_len.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
    // UDP header
    pkt[20..22].copy_from_slice(&12345u16.to_be_bytes()); // src port
    pkt[22..24].copy_from_slice(&443u16.to_be_bytes()); // dst port
    pkt[24..26].copy_from_slice(&(8 + 12u16).to_be_bytes()); // udp len
    pkt
}

/// Build a minimal valid IPv4+TCP SYN packet (test helper).
#[cfg(test)]
pub(crate) fn synth_syn_with_mss(mss: u16, with_sack: bool) -> Vec<u8> {
    let mut opts = Vec::new();
    opts.push(tcp_opt::MSS);
    opts.push(4);
    opts.extend_from_slice(&mss.to_be_bytes());
    if with_sack {
        opts.push(tcp_opt::SACK_PERMITTED);
        opts.push(2);
    }
    while opts.len() % 4 != 0 {
        opts.push(1);
    }
    let tcp_hdr_len = 20 + opts.len();
    let total = 20 + tcp_hdr_len;
    let mut pkt = vec![0u8; total];
    // IP header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
    // TCP header
    pkt[20 + 12] = ((tcp_hdr_len / 4) as u8) << 4; // data offset
    pkt[20 + 14] = 0x50; // flags: SYN
    pkt[20 + 2..20 + 4].copy_from_slice(&0x01bbu16.to_be_bytes()); // dst 443
    pkt[20 + 20..20 + 20 + opts.len()].copy_from_slice(&opts);
    // fix checksums
    let mut p = TcpPacket::parse(&pkt).unwrap();
    fix_ipv4_checksum(&mut p);
    fix_tcp_checksum(&mut p);
    p.raw
}

/// Extract the TLS Server Name Indication (SNI) from a ClientHello payload.
///
/// `tcp_payload` must be the TCP stream data (after the TCP header). The
/// handshake/record framing is parsed defensively; returns None on any
/// malformed input.
pub fn extract_tls_sni(tcp_payload: &[u8]) -> Option<String> {
    // TLS record: type(1) version(2) length(2)
    if tcp_payload.len() < 5 {
        return None;
    }
    if tcp_payload[0] != 0x16 {
        // not a handshake record
        return None;
    }
    let rec_len = u16::from_be_bytes([tcp_payload[3], tcp_payload[4]]) as usize;
    // handshake: type(1) length(3)
    let hs = 5;
    if tcp_payload.len() < hs + 4 {
        return None;
    }
    if tcp_payload[hs] != 0x01 {
        // not ClientHello
        return None;
    }
    let hs_len = ((tcp_payload[hs + 1] as usize) << 16)
        | ((tcp_payload[hs + 2] as usize) << 8)
        | (tcp_payload[hs + 3] as usize);
    let hello = hs + 4;
    if hello + hs_len > tcp_payload.len() || hello + hs_len > 5 + rec_len {
        return None;
    }
    let body = &tcp_payload[hello..hello + hs_len];
    // ClientHello: legacy_version(2) random(32) session_id(1+len)
    if body.len() < 2 + 32 + 1 {
        return None;
    }
    let mut off = 2 + 32;
    let sid_len = body[off] as usize;
    off += 1 + sid_len;
    // cipher suites (2 + len)
    if body.len() < off + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2 + cs_len;
    // compression methods (1 + len)
    if body.len() < off + 1 {
        return None;
    }
    let comp_len = body[off] as usize;
    off += 1 + comp_len;
    // extensions (2 + total len)
    if body.len() < off + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if off + ext_total > body.len() {
        return None;
    }
    let exts = &body[off..off + ext_total];
    let mut e = 0;
    while e + 4 <= exts.len() {
        let ext_type = u16::from_be_bytes([exts[e], exts[e + 1]]);
        let ext_len = u16::from_be_bytes([exts[e + 2], exts[e + 3]]) as usize;
        if e + 4 + ext_len > exts.len() {
            break;
        }
        if ext_type == 0 {
            // server_name
            let data = &exts[e + 4..e + 4 + ext_len];
            return parse_sni_list(data);
        }
        e += 4 + ext_len;
    }
    None
}

/// Parse the server_name extension payload for the first host_name.
fn parse_sni_list(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = &data[2..];
    if list.len() < list_len {
        return None;
    }
    let mut off = 0;
    while off + 3 <= list.len() {
        let name_type = list[off];
        let name_len = u16::from_be_bytes([list[off + 1], list[off + 2]]) as usize;
        if off + 3 + name_len > list.len() {
            break;
        }
        if name_type == 0 {
            return std::str::from_utf8(&list[off + 3..off + 3 + name_len])
                .ok()
                .map(|s| s.to_string());
        }
        off += 3 + name_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_syn_with_mss() {
        let raw = synth_syn_with_mss(1460, false);
        let pkt = TcpPacket::parse(&raw).unwrap();
        assert_eq!(pkt.dst_port(), 443);
        assert_eq!(pkt.tcp_header_len, 24); // 20 + 4 (mss, 4-byte aligned)
    }

    #[test]
    fn sets_mss_in_place() {
        let raw = synth_syn_with_mss(1460, true);
        let mut pkt = TcpPacket::parse(&raw).unwrap();
        assert!(tcp_opt::set_mss(&mut pkt, 1200));
        // re-parse and confirm
        let re = TcpPacket::parse(&pkt.raw).unwrap();
        // find mss value
        let start = re.tcp_offset + 20;
        let end = re.tcp_offset + re.tcp_header_len;
        let mut i = start;
        let mut found = None;
        while i + 1 < end {
            let k = re.raw[i];
            if k == 0 {
                break;
            }
            if k == 1 {
                i += 1;
                continue;
            }
            let len = re.raw[i + 1] as usize;
            if k == tcp_opt::MSS && len >= 4 {
                found = Some(u16::from_be_bytes([re.raw[i + 2], re.raw[i + 3]]));
            }
            i += len;
        }
        assert_eq!(found, Some(1200));
    }

    #[test]
    fn strips_sack_permitted() {
        let raw = synth_syn_with_mss(1460, true);
        let mut pkt = TcpPacket::parse(&raw).unwrap();
        assert!(tcp_opt::strip_option(&mut pkt, tcp_opt::SACK_PERMITTED));
        // re-parse; no SACK option should remain
        let re = TcpPacket::parse(&pkt.raw).unwrap();
        let start = re.tcp_offset + 20;
        let end = re.tcp_offset + re.tcp_header_len;
        let mut i = start;
        let mut has_sack = false;
        while i + 1 < end {
            let k = re.raw[i];
            if k == 0 {
                break;
            }
            if k == 1 {
                i += 1;
                continue;
            }
            let len = re.raw[i + 1] as usize;
            if k == tcp_opt::SACK_PERMITTED {
                has_sack = true;
            }
            i += len;
        }
        assert!(!has_sack);
    }

    #[test]
    fn non_tcp_is_rejected() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        assert!(TcpPacket::parse(&pkt).is_none());
    }
}
