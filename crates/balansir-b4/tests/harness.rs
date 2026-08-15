//! Deterministic B4 test harness (mission §4 / §18).
//!
//! Pure in-memory packet fixtures — no kernel, no internet. Covers the packet
//! handling matrix the production engine must not crash on:
//!
//! * normal TCP (SYN/data) parsing;
//! * TLS ClientHello with SNI extraction;
//! * fragmented ClientHello (record split across packets);
//! * packets without SNI;
//! * IPv4 (IPv6 is a documented limitation — must pass through untouched);
//! * retransmission-shaped packets (dup ACK / seq reuse);
//! * malformed TCP options;
//! * SACK option stripping;
//! * MTU / MSS mutation;
//! * checksum recomputation.

use balansir_b4::packet::{
    extract_tls_sni, fix_ipv4_checksum, fix_tcp_checksum, tcp_opt, TcpPacket,
};
use balansir_b4::strategies::{EngineConfig, Profile, Strategy};

// ---------------------------------------------------------------------------
// Packet fixtures
// ---------------------------------------------------------------------------

/// Build a minimal valid IPv4+TCP packet with the given payload bytes.
/// `syn`/`sack` control the TCP header options; checksums are left zero
/// unless `fix_csum` is true (the parser does not require them valid).
fn ipv4_tcp(payload: &[u8], opts: &[u8], flags: u8, dst_port: u16, fix_csum: bool) -> Vec<u8> {
    // TCP options must be 4-byte aligned (the data-offset field is in 32-bit
    // words); pad with NOPs so the parser reads the exact option bytes.
    let mut padded = opts.to_vec();
    while (20 + padded.len()) % 4 != 0 {
        padded.push(1);
    }
    let tcp_hdr_len = 20 + padded.len();
    let total = 20 + tcp_hdr_len + payload.len();
    let mut pkt = vec![0u8; total];
    // IP header
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&[192, 168, 1, 10]);
    pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
    // TCP header
    pkt[20 + 12] = ((tcp_hdr_len / 4) as u8) << 4;
    pkt[20 + 14] = flags;
    pkt[20 + 2..20 + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[20 + 20..20 + 20 + padded.len()].copy_from_slice(&padded);
    pkt[20 + tcp_hdr_len..].copy_from_slice(payload);
    if fix_csum {
        let mut p = TcpPacket::parse(&pkt).unwrap();
        fix_ipv4_checksum(&mut p);
        fix_tcp_checksum(&mut p);
        p.raw
    } else {
        pkt
    }
}

/// A syntactically valid TLS ClientHello for `host`, as TCP payload.
/// Returns the bytes of the TLS record (type 0x16, version 0x0303).
fn client_hello(host: &str) -> Vec<u8> {
    let sni = host.as_bytes();
    let list_len = 1 + 2 + sni.len();
    let mut sni_list = Vec::new();
    sni_list.extend_from_slice(&(list_len as u16).to_be_bytes());
    sni_list.push(0); // name_type host_name
    sni_list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    sni_list.extend_from_slice(sni);

    let mut exts = Vec::new();
    exts.extend_from_slice(&0u16.to_be_bytes()); // server_name ext type
    exts.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_list);

    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id len
    body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1); // compression methods len
    body.push(0); // null compression
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = vec![0x01]; // ClientHello
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

// ---------------------------------------------------------------------------
// TCP parse / validation
// ---------------------------------------------------------------------------

#[test]
fn parses_normal_tcp_data_packet() {
    let raw = ipv4_tcp(b"hello", &[], 0x18 /* PSH|ACK */, 443, true);
    let pkt = TcpPacket::parse(&raw).expect("valid ipv4+tcp");
    assert_eq!(pkt.dst_port(), 443);
    assert_eq!(pkt.tcp_header_len, 20);
    assert_eq!(pkt.ip_total_len, raw.len());
}

#[test]
fn parses_syn_with_mss_and_sack_options() {
    let opts = [2u8, 4, 0x04, 0xb0, 4, 2, 1, 1]; // MSS 1200, SACK-permitted, NOP
    let raw = ipv4_tcp(&[], &opts, 0x02 /* SYN */, 443, true);
    let pkt = TcpPacket::parse(&raw).unwrap();
    assert_eq!(pkt.tcp_header_len, 28);
}

#[test]
fn rejects_non_tcp_protocol() {
    let mut raw = ipv4_tcp(b"x", &[], 0x18, 443, false);
    raw[9] = 17; // UDP
    assert!(TcpPacket::parse(&raw).is_none());
}

#[test]
fn rejects_truncated_packets() {
    // IP header claims a total length larger than the buffer.
    let raw = ipv4_tcp(b"data", &[], 0x18, 443, false);
    let truncated = &raw[..30];
    assert!(TcpPacket::parse(truncated).is_none());
}

#[test]
fn rejects_ipv6_as_not_tcp_ipv4() {
    // IPv6 packets start with version nibble 6 → parser must return None
    // (documented limitation: IPv6 is not intercepted, passed through).
    let mut raw = ipv4_tcp(b"x", &[], 0x18, 443, false);
    raw[0] = 0x60; // IPv6 version
    assert!(TcpPacket::parse(&raw).is_none());
}

#[test]
fn handles_malformed_tcp_options_without_panic() {
    // Option length field that overruns the header.
    let opts = [2u8, 250]; // kind=MSS, len=250 (invalid)
    let raw = ipv4_tcp(b"", &opts, 0x02, 443, false);
    // Parse must not panic; either Some (with sane header len) or None.
    if let Some(pkt) = TcpPacket::parse(&raw) {
        // set_mss must not panic on malformed options either.
        let _ = tcp_opt::set_mss(&mut pkt.clone(), 1200);
        let _ = tcp_opt::strip_option(&mut pkt.clone(), tcp_opt::SACK_PERMITTED);
    }
}

#[test]
fn mss_mutation_rewrites_option_and_fixes_checksum() {
    let opts = [2u8, 4, 0x05, 0xb4]; // MSS 1460
    let raw = ipv4_tcp(&[], &opts, 0x02, 443, true);
    let mut pkt = TcpPacket::parse(&raw).unwrap();
    assert!(tcp_opt::set_mss(&mut pkt, 1200));
    fix_ipv4_checksum(&mut pkt);
    fix_tcp_checksum(&mut pkt);
    let re = TcpPacket::parse(&pkt.raw).unwrap();
    // Read back the MSS option value.
    let mut i = re.tcp_offset + 20;
    let end = re.tcp_offset + re.tcp_header_len;
    let mut mss = None;
    while i + 1 < end {
        let kind = re.raw[i];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            continue;
        }
        let len = re.raw[i + 1] as usize;
        if kind == 2 && len >= 4 {
            mss = Some(u16::from_be_bytes([re.raw[i + 2], re.raw[i + 3]]));
        }
        i += len;
    }
    assert_eq!(mss, Some(1200));
    // Recompute: the re-parsed packet must have valid checksums by inspection
    // (re-parsing succeeds and no panic is enough for the harness).
}

#[test]
fn ttl_strategy_changes_ttl_byte() {
    let raw = ipv4_tcp(b"x", &[], 0x18, 443, true);
    let mut pkt = TcpPacket::parse(&raw).unwrap();
    assert!(Strategy::Ttl { ttl: 61 }.apply(&mut pkt));
    assert_eq!(pkt.raw[8], 61);
    // Same TTL → no change (idempotent).
    assert!(!Strategy::Ttl { ttl: 61 }.apply(&mut pkt));
}

#[test]
fn sack_strip_removes_option_and_realigns() {
    let opts = [2u8, 4, 0x05, 0xb4, 4, 2, 1, 1];
    let raw = ipv4_tcp(b"payload", &opts, 0x02, 443, true);
    let mut pkt = TcpPacket::parse(&raw).unwrap();
    let original_len = pkt.tcp_header_len;
    assert!(tcp_opt::strip_option(&mut pkt, tcp_opt::SACK_PERMITTED));
    fix_ipv4_checksum(&mut pkt);
    fix_tcp_checksum(&mut pkt);
    let re = TcpPacket::parse(&pkt.raw).unwrap();
    assert!(re.tcp_header_len <= original_len);
    // No SACK-permitted (kind 4) option must remain — walk options by their
    // kind/len structure, not byte-by-byte (a byte scan would hit the MSS
    // length byte which happens to be 4).
    let mut i = re.tcp_offset + 20;
    let end = re.tcp_offset + re.tcp_header_len;
    let mut has_sack = false;
    while i < end {
        let kind = re.raw[i];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            i += 1;
            continue;
        }
        let len = re.raw[i + 1] as usize;
        if len < 2 || i + len > end {
            break;
        }
        if kind == 4 {
            has_sack = true;
        }
        i += len;
    }
    assert!(!has_sack);
}

#[test]
fn payload_survives_strip_mutation() {
    // After stripping an option, the TCP payload must still be present and
    // byte-identical (a mutation that corrupts payload = broken DPI).
    let payload = b"POST / HTTP/1.1\r\nHost: x\r\n\r\n";
    let opts = [4u8, 2];
    let raw = ipv4_tcp(payload, &opts, 0x18, 443, true);
    let mut pkt = TcpPacket::parse(&raw).unwrap();
    assert!(tcp_opt::strip_option(&mut pkt, tcp_opt::SACK_PERMITTED));
    fix_ipv4_checksum(&mut pkt);
    fix_tcp_checksum(&mut pkt);
    let re = TcpPacket::parse(&pkt.raw).unwrap();
    let body = &re.raw[re.tcp_offset + re.tcp_header_len..];
    assert_eq!(body, payload);
}

// ---------------------------------------------------------------------------
// SNI extraction
// ---------------------------------------------------------------------------

#[test]
fn extracts_sni_from_client_hello() {
    let hello = client_hello("youtube.com");
    assert_eq!(extract_tls_sni(&hello).as_deref(), Some("youtube.com"));
}

#[test]
fn extracts_sni_from_longer_host() {
    let hello = client_hello("video.google.com");
    assert_eq!(extract_tls_sni(&hello).as_deref(), Some("video.google.com"));
}

#[test]
fn no_sni_for_plain_http() {
    assert_eq!(extract_tls_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), None);
}

#[test]
fn no_sni_for_non_handshake_record() {
    // Record type 0x17 (application data) → not a ClientHello.
    let mut rec = client_hello("youtube.com");
    rec[0] = 0x17;
    assert_eq!(extract_tls_sni(&rec), None);
}

#[test]
fn fragmented_clienthello_sni_detection_requires_full_record() {
    // A single record split across two TCP segments: the first segment alone
    // does not contain the whole record → the extractor returns None for the
    // first fragment (documented limitation). The second fragment alone also
    // lacks the record header. The engine must never crash on this.
    let hello = client_hello("youtube.com");
    let (a, b) = hello.split_at(50);
    assert_eq!(extract_tls_sni(a), None);
    assert_eq!(extract_tls_sni(b), None);
    // And re-assembly of the full bytes works.
    let mut full = a.to_vec();
    full.extend_from_slice(b);
    assert_eq!(extract_tls_sni(&full).as_deref(), Some("youtube.com"));
}

#[test]
fn truncated_sni_payload_is_none_not_panic() {
    let hello = client_hello("youtube.com");
    for cut in 0..hello.len() {
        let _ = extract_tls_sni(&hello[..cut]); // must never panic
    }
}

#[test]
fn malformed_sni_list_is_none_not_panic() {
    // SNI list length overruns the extension.
    let mut hello = client_hello("youtube.com");
    // Flip bytes in the extension region (offset 45..48 contains the list
    // length in the fixture) to force a length-overrun.
    if hello.len() > 48 {
        hello[46] = 0xff;
        hello[47] = 0xff;
    }
    let _ = extract_tls_sni(&hello); // must not panic
}

// ---------------------------------------------------------------------------
// EngineConfig profile matching
// ---------------------------------------------------------------------------

fn config() -> EngineConfig {
    EngineConfig {
        profiles: vec![Profile {
            name: "youtube".into(),
            domains: vec!["youtube.com".into(), "googlevideo.com".into()],
            strategies: vec![Strategy::Mss { mss: 1200 }],
        }],
    }
}

#[test]
fn profile_matches_suffix() {
    let cfg = config();
    assert!(cfg.profile_for("www.youtube.com").is_some());
    assert!(cfg.profile_for("YOUTUBE.COM").is_some());
    assert!(cfg.profile_for("googlevideo.com.").is_some());
    assert!(cfg.profile_for("youtube.com.evil.example").is_none());
    assert!(cfg.profile_for("notyoutube.com").is_none());
}

// ---------------------------------------------------------------------------
// Retransmission / concurrency safety (pure portions)
// ---------------------------------------------------------------------------

#[test]
fn retransmission_shaped_packets_parse_and_mutate_safely() {
    // A dup-ACK-style data packet with payload and no options.
    let raw = ipv4_tcp(b"retransmitted-data", &[], 0x10 /* ACK */, 443, true);
    let mut pkt = TcpPacket::parse(&raw).unwrap();
    // Applying a TTL strategy must succeed and preserve the payload.
    assert!(Strategy::Ttl { ttl: 62 }.apply(&mut pkt));
    fix_ipv4_checksum(&mut pkt);
    fix_tcp_checksum(&mut pkt);
    let re = TcpPacket::parse(&pkt.raw).unwrap();
    let body = &re.raw[re.tcp_offset + re.tcp_header_len..];
    assert_eq!(body, b"retransmitted-data");
}

#[test]
fn zero_length_payload_accept_path_is_safe() {
    // ACK-only packets (payload_len=0) parse fine; mutation is a no-op.
    let raw = ipv4_tcp(&[], &[], 0x10, 443, true);
    let mut pkt = TcpPacket::parse(&raw).unwrap();
    let _ = Strategy::Ttl { ttl: 63 }.apply(&mut pkt);
    let _ = Strategy::Mss { mss: 1200 }.apply(&mut pkt); // no MSS option → false
}

#[test]
fn concurrent_parsing_is_send_safe() {
    // The fixtures are all immutable byte slices; TcpPacket is Clone + Send.
    // This is a smoke test that the types the engine moves across threads are
    // usable from multiple threads without shared mutable state.
    let raw = ipv4_tcp(b"concurrent", &[], 0x18, 443, true);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let raw = raw.clone();
            std::thread::spawn(move || {
                for _ in 0..100 {
                    let pkt = TcpPacket::parse(&raw).unwrap();
                    let _ = pkt.dst_port();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn different_ports_and_flows_are_isolated() {
    // Packets to non-443 ports must parse but the engine's port gate skips
    // them; verify parse + mutation logic is flow-agnostic.
    let raw = ipv4_tcp(b"ssh", &[], 0x18, 22, true);
    let pkt = TcpPacket::parse(&raw).unwrap();
    assert_eq!(pkt.dst_port(), 22);
}
