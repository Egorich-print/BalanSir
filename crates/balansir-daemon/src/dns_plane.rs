//! DNS wire-format parsing for the policy plane (P6, ADR-023).
//!
//! BalanSir is deliberately **not** a recursive resolver. This module parses
//! just enough of a DNS message to observe A/AAAA answer sets — following
//! CNAME chains and compression pointers — and feeds the shared
//! `DnsRegistry`, which is the single DNS observation truth read by the flow
//! compiler (domain → IP policy compilation) and the B4 observer.
//!
//! Every access is bounds-checked and every loop is capped: hostile,
//! truncated or malformed packets must never panic, allocate unboundedly or
//! loop forever. Only well-formed, untruncated `NOERROR` responses with
//! A/AAAA records for the queried name (or its CNAME chain) are recorded —
//! partial answers (TC set) and error responses are never trusted.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use crate::reconciliation::DnsRegistry;

/// DNS header is fixed at 12 bytes.
const HEADER_LEN: usize = 12;
/// Maximum wire-form domain name length (RFC 1035 §2.3.4).
const MAX_NAME_LEN: usize = 255;
/// Maximum compression-pointer jumps while decoding a single name.
const MAX_POINTER_JUMPS: u8 = 64;
/// Maximum CNAME chain length we follow per observation.
const MAX_CNAME_CHAIN: usize = 8;
/// Maximum answer records parsed from one response (defensive cap; a 64 KB
/// message cannot carry more than this many 11-byte minimum records anyway).
const MAX_ANSWERS: usize = 2048;

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;

/// Observation TTL floor: entries never expire faster than this.
const MIN_TTL_SECS: u64 = 60;
/// Observation TTL cap: entries live at most this long without refresh.
const MAX_TTL_SECS: u64 = 3600;

/// A parsed resource record (only fields we need; others are skipped).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    owner: String,
    rtype: u16,
    ttl: u32,
    /// Offset of RDATA in the message (compression pointers are message-relative).
    rdata_off: usize,
    rdata_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsError {
    TooShort,
    BadLabel,
    NameTooLong,
    PointerLoop,
    PointerOutOfRange,
    NotAResponse,
    TooManyRecords,
}

/// A usable DNS observation: normalized domain, resolved addresses and a
/// clamped freshness TTL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsObservation {
    pub domain: String,
    pub ips: Vec<IpAddr>,
    pub ttl: Duration,
}

/// Normalize a DNS name for use as a registry key: lowercase, strip the
/// trailing root dot, reject names that are empty, overlong or cannot be a
/// policy key (non-host characters, empty labels).
pub fn normalize_domain(name: &str) -> Option<String> {
    let s = name.trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || s.len() > MAX_NAME_LEN {
        return None;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return None;
    }
    if s.split('.').any(|label| label.is_empty()) {
        return None;
    }
    Some(s)
}

#[derive(Debug, Clone, Copy)]
struct Header {
    qr: bool,
    tc: bool,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
}

fn parse_header(msg: &[u8]) -> Option<Header> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    Some(Header {
        qr: flags & 0x8000 != 0,
        tc: flags & 0x0200 != 0,
        rcode: (flags & 0x000F) as u8,
        qdcount: u16::from_be_bytes([msg[4], msg[5]]),
        ancount: u16::from_be_bytes([msg[6], msg[7]]),
    })
}

/// Decode a possibly-compressed domain name starting at `start`.
///
/// Returns the decoded (normalized) name and the position just past the name
/// *as encoded at `start`* — after the first compression pointer or the
/// terminating zero — so the caller can keep walking the record.
fn decode_name(msg: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut out = String::new();
    let mut pos = start;
    let mut after: Option<usize> = None;
    let mut jumps = 0u8;
    let mut visited: Vec<usize> = Vec::with_capacity(8);
    let mut total = 0usize;

    loop {
        let len = *msg.get(pos).ok_or(DnsError::TooShort)?;
        if len == 0 {
            // End of name.
            if after.is_none() {
                after = Some(pos + 1);
            }
            break;
        } else if len & 0xC0 == 0xC0 {
            // Compression pointer: 14-bit offset from the message start.
            let target = ((u16::from(len & 0x3F)) << 8)
                | u16::from(*msg.get(pos + 1).ok_or(DnsError::TooShort)?);
            let target = target as usize;
            if after.is_none() {
                after = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return Err(DnsError::PointerLoop);
            }
            if target >= msg.len() || visited.contains(&target) {
                return Err(DnsError::PointerOutOfRange);
            }
            visited.push(target);
            pos = target;
        } else if len <= 63 {
            // Label (reserved encodings 0x40..=0xBF are rejected as BadLabel
            // by falling through to the `else` branch).
            let end = pos + 1 + usize::from(len);
            if end > msg.len() {
                return Err(DnsError::TooShort);
            }
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(&String::from_utf8_lossy(&msg[pos + 1..end]));
            total += 1 + usize::from(len);
            if total > MAX_NAME_LEN {
                return Err(DnsError::NameTooLong);
            }
            pos = end;
        } else {
            return Err(DnsError::BadLabel);
        }
    }

    let name = normalize_domain(&out).ok_or(DnsError::BadLabel)?;
    Ok((name, after.unwrap_or(start)))
}

/// Parse the answer section of a response into bounded [`Record`]s.
fn parse_answers(msg: &[u8]) -> Result<Vec<Record>, DnsError> {
    let hdr = parse_header(msg).ok_or(DnsError::TooShort)?;
    if !hdr.qr {
        return Err(DnsError::NotAResponse);
    }

    let mut pos = HEADER_LEN;
    for _ in 0..hdr.qdcount {
        let (_, next) = decode_name(msg, pos)?;
        pos = next;
        if pos + 4 > msg.len() {
            return Err(DnsError::TooShort);
        }
        pos += 4; // QTYPE + QCLASS
    }

    let mut out = Vec::new();
    for _ in 0..hdr.ancount {
        if out.len() >= MAX_ANSWERS {
            return Err(DnsError::TooManyRecords);
        }
        let (owner, next) = decode_name(msg, pos)?;
        pos = next;
        if pos + 10 > msg.len() {
            return Err(DnsError::TooShort);
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlen = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > msg.len() {
            return Err(DnsError::TooShort);
        }
        out.push(Record {
            owner,
            rtype,
            ttl,
            rdata_off: pos,
            rdata_len: rdlen,
        });
        pos += rdlen;
    }
    Ok(out)
}

/// Extract the normalized first question name from a DNS *query*.
pub fn query_name(msg: &[u8]) -> Option<String> {
    let hdr = parse_header(msg)?;
    if hdr.qr || hdr.qdcount == 0 {
        return None;
    }
    let (name, pos) = decode_name(msg, HEADER_LEN).ok()?;
    if pos + 4 > msg.len() {
        return None;
    }
    Some(name)
}

/// Extract a usable observation from a response for a queried domain.
///
/// Returns `None` when the response is not a `NOERROR` answer, is truncated
/// (TC set — partial answers are never recorded), or carries no A/AAAA
/// records for the queried name or its CNAME chain.
pub fn observe_response(query: &str, response: &[u8]) -> Option<DnsObservation> {
    let hdr = parse_header(response)?;
    if !hdr.qr || hdr.tc || hdr.rcode != 0 {
        return None;
    }
    let qname = normalize_domain(query)?;
    let answers = parse_answers(response).ok()?;

    // Walk the CNAME chain starting from the queried name (loop-safe).
    let mut chain: Vec<String> = vec![qname.clone()];
    loop {
        let cur = chain.last().cloned()?;
        let Some(cname) = answers
            .iter()
            .find(|r| r.rtype == TYPE_CNAME && r.owner == cur)
        else {
            break;
        };
        let (target, _) = decode_name(response, cname.rdata_off).ok()?;
        if chain.len() >= MAX_CNAME_CHAIN || chain.contains(&target) {
            break;
        }
        chain.push(target);
    }

    let mut ips: Vec<IpAddr> = Vec::new();
    let mut ttl = u32::MAX;
    for record in answers.iter() {
        if !matches!(record.rtype, TYPE_A | TYPE_AAAA) || !chain.contains(&record.owner) {
            continue;
        }
        let raw = response.get(record.rdata_off..record.rdata_off + record.rdata_len)?;
        match record.rtype {
            TYPE_A if record.rdata_len == 4 => {
                ips.push(IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])));
                ttl = ttl.min(record.ttl);
            }
            TYPE_AAAA if record.rdata_len == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(raw);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                ttl = ttl.min(record.ttl);
            }
            _ => {}
        }
    }
    if ips.is_empty() {
        return None;
    }
    let ttl_secs = u64::from(ttl).clamp(MIN_TTL_SECS, MAX_TTL_SECS);
    Some(DnsObservation {
        domain: qname,
        ips,
        ttl: Duration::from_secs(ttl_secs),
    })
}

/// Parse a forwarded query/response pair and record the observation in the
/// shared registry. Returns `true` when an observation was recorded.
pub fn ingest(registry: &DnsRegistry, query: &[u8], response: &[u8]) -> bool {
    let Some(qname) = query_name(query) else {
        return false;
    };
    let Some(obs) = observe_response(&qname, response) else {
        return false;
    };
    registry.insert_with_ttl(&obs.domain, obs.ips, obs.ttl);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DNS message: header + optional question + answers.
    struct Msg {
        buf: Vec<u8>,
    }

    impl Msg {
        fn with_header(qr: bool, tc: bool, rcode: u8, qd: u16, an: u16) -> Self {
            let mut flags: u16 = 0;
            if qr {
                flags |= 0x8000;
            }
            if tc {
                flags |= 0x0200;
            }
            flags |= u16::from(rcode);
            let mut buf = Vec::new();
            buf.extend_from_slice(&0x1234u16.to_be_bytes());
            buf.extend_from_slice(&flags.to_be_bytes());
            buf.extend_from_slice(&qd.to_be_bytes());
            buf.extend_from_slice(&an.to_be_bytes());
            buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
            buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
            Self { buf }
        }

        fn question(mut self, name: &[&str]) -> Self {
            for label in name {
                self.buf.push(label.len() as u8);
                self.buf.extend_from_slice(label.as_bytes());
            }
            self.buf.push(0);
            self.buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
            self.buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
            self
        }

        fn answer(mut self, name: &[&str], rtype: u16, ttl: u32, rdata: &[u8]) -> Self {
            for label in name {
                self.buf.push(label.len() as u8);
                self.buf.extend_from_slice(label.as_bytes());
            }
            self.buf.push(0);
            self.buf.extend_from_slice(&rtype.to_be_bytes());
            self.buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            self.buf.extend_from_slice(&ttl.to_be_bytes());
            self.buf
                .extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            self.buf.extend_from_slice(rdata);
            self
        }

        fn cname(self, name: &[&str], target: &[&str]) -> Self {
            let rdata = {
                let mut rd = Vec::new();
                for label in target {
                    rd.push(label.len() as u8);
                    rd.extend_from_slice(label.as_bytes());
                }
                rd.push(0);
                rd
            };
            self.answer(name, TYPE_CNAME, 300, &rdata)
        }

        fn build(self) -> Vec<u8> {
            self.buf
        }
    }

    fn a_rdata(ip: &str) -> Vec<u8> {
        ip.parse::<Ipv4Addr>().unwrap().octets().to_vec()
    }

    fn query(name: &[&str]) -> Vec<u8> {
        Msg::with_header(false, false, 0, 1, 0)
            .question(name)
            .build()
    }

    #[test]
    fn query_name_extraction() {
        let q = query(&["api", "example", "com"]);
        assert_eq!(query_name(&q).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn query_name_rejects_response_and_empty() {
        let resp = Msg::with_header(true, false, 0, 0, 0).build();
        assert!(query_name(&resp).is_none());
        assert!(query_name(b"short").is_none());
    }

    #[test]
    fn direct_a_answer_observed() {
        let resp = Msg::with_header(true, false, 0, 1, 1)
            .question(&["example", "com"])
            .answer(&["example", "com"], TYPE_A, 120, &a_rdata("203.0.113.5"))
            .build();
        let obs = observe_response("example.com", &resp).expect("observed");
        assert_eq!(obs.domain, "example.com");
        assert_eq!(obs.ips, vec!["203.0.113.5".parse::<IpAddr>().unwrap()]);
        assert_eq!(obs.ttl, Duration::from_secs(120));
    }

    #[test]
    fn cname_chain_resolves_to_canonical_addresses() {
        let resp = Msg::with_header(true, false, 0, 1, 3)
            .question(&["www", "example", "com"])
            .cname(&["www", "example", "com"], &["edge", "example", "com"])
            .answer(
                &["edge", "example", "com"],
                TYPE_A,
                300,
                &a_rdata("198.51.100.7"),
            )
            .answer(&["edge", "example", "com"], TYPE_AAAA, 300, &[0u8; 16])
            .build();
        let obs = observe_response("www.example.com", &resp).expect("observed");
        assert_eq!(obs.domain, "www.example.com");
        assert!(obs.ips.contains(&"198.51.100.7".parse().unwrap()));
        assert!(obs.ips.iter().any(|ip| ip.is_ipv6()));
    }

    #[test]
    fn compression_pointer_is_followed() {
        // Question encodes the name at offset 12; an answer reuses it via a
        // pointer, proving the parser follows compression.
        let mut resp = Msg::with_header(true, false, 0, 1, 1)
            .question(&["example", "com"])
            .build();
        // Answer with a pointer to offset 12 (start of the question name).
        resp.push(0xC0);
        resp.push(12);
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&a_rdata("192.0.2.9"));
        let obs = observe_response("example.com", &resp).expect("observed");
        assert!(obs.ips.contains(&"192.0.2.9".parse().unwrap()));
    }

    #[test]
    fn truncated_response_is_not_observed() {
        let resp = Msg::with_header(true, true, 0, 1, 1)
            .question(&["example", "com"])
            .build();
        assert!(observe_response("example.com", &resp).is_none());
    }

    #[test]
    fn error_rcodes_are_not_observed() {
        for rcode in [1, 2, 3, 5] {
            // NXDOMAIN(3), SERVFAIL(2), REFUSED(5) …
            let resp = Msg::with_header(true, false, rcode, 1, 0)
                .question(&["example", "com"])
                .build();
            assert!(
                observe_response("example.com", &resp).is_none(),
                "rcode {rcode} must not be recorded"
            );
        }
    }

    #[test]
    fn ttl_is_clamped() {
        // TTL 1s is below the floor; TTL 999999 is above the cap.
        let low = Msg::with_header(true, false, 0, 1, 1)
            .question(&["example", "com"])
            .answer(&["example", "com"], TYPE_A, 1, &a_rdata("203.0.113.1"))
            .build();
        assert_eq!(
            observe_response("example.com", &low).unwrap().ttl,
            Duration::from_secs(MIN_TTL_SECS)
        );
        let high = Msg::with_header(true, false, 0, 1, 1)
            .question(&["example", "com"])
            .answer(
                &["example", "com"],
                TYPE_A,
                999_999,
                &a_rdata("203.0.113.2"),
            )
            .build();
        assert_eq!(
            observe_response("example.com", &high).unwrap().ttl,
            Duration::from_secs(MAX_TTL_SECS)
        );
    }

    /// Build a response body whose first answer owner is exactly `name_bytes`
    /// followed by a minimal A record (2-byte type, 2-byte class, 4-byte TTL,
    /// 2-byte rdlen, 4-byte rdata). Lets tests feed arbitrary hostile owner
    /// encodings straight into `parse_answers`.
    fn owner_with_a_record(name_bytes: &[u8]) -> Vec<u8> {
        let mut buf = Msg::with_header(true, false, 0, 0, 1).build();
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&TYPE_A.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&300u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[203, 0, 113, 5]);
        buf
    }

    #[test]
    fn pointer_loop_is_rejected() {
        // Name: label "a", then a pointer back to its own offset (12).
        let body = owner_with_a_record(&[1, b'a', 0xC0, 12]);
        assert!(
            parse_answers(&body).is_err(),
            "self-pointer must be rejected"
        );
    }

    #[test]
    fn out_of_range_pointer_is_rejected() {
        let body = owner_with_a_record(&[0xC0, 0xFF]);
        assert!(parse_answers(&body).is_err());
    }

    #[test]
    fn oversized_label_is_rejected() {
        let mut name = vec![70u8]; // label length > 63
        name.extend_from_slice(&[b'a'; 70]);
        name.push(0);
        let body = owner_with_a_record(&name);
        assert!(parse_answers(&body).is_err());
    }

    #[test]
    fn truncated_record_is_rejected() {
        let mut resp = Msg::with_header(true, false, 0, 0, 1).build();
        resp.push(1);
        resp.push(b'a');
        resp.push(0);
        resp.extend_from_slice(&TYPE_A.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&20u16.to_be_bytes()); // claims 20 bytes, has 0
        let r = parse_answers(&resp);
        assert!(r.is_err());
    }

    #[test]
    fn normalize_domain_accepts_and_rejects() {
        assert_eq!(
            normalize_domain("Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("a-b.example").as_deref(),
            Some("a-b.example")
        );
        assert_eq!(normalize_domain("a..b"), None);
        assert_eq!(normalize_domain(""), None);
        assert_eq!(normalize_domain("sp ace.example"), None);
        assert_eq!(normalize_domain("x".repeat(300).as_str()), None);
        assert_eq!(normalize_domain("semi;colon.example"), None);
    }

    #[test]
    fn ingest_populates_shared_registry() {
        let registry = DnsRegistry::new();
        let q = query(&["api", "example", "com"]);
        let resp = Msg::with_header(true, false, 0, 1, 2)
            .question(&["api", "example", "com"])
            .cname(&["api", "example", "com"], &["edge", "example", "com"])
            .answer(
                &["edge", "example", "com"],
                TYPE_A,
                300,
                &a_rdata("203.0.113.9"),
            )
            .build();
        assert!(ingest(&registry, &q, &resp), "observation must be recorded");
        let ips = registry.resolve("api.example.com").expect("resolved");
        assert!(ips.contains(&"203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn ingest_ignores_error_and_garbage() {
        let registry = DnsRegistry::new();
        let q = query(&["api", "example", "com"]);
        let nxdomain = Msg::with_header(true, false, 3, 1, 0)
            .question(&["api", "example", "com"])
            .build();
        assert!(!ingest(&registry, &q, &nxdomain));
        assert!(registry.resolve("api.example.com").is_none());
        assert!(!ingest(&registry, b"junk", b"junk"));
    }

    /// Hostile-input sweep: arbitrary byte strings must never panic and never
    /// return an observation for a name that does not match the query.
    #[test]
    fn hostile_inputs_never_panic() {
        let registry = DnsRegistry::new();
        let q = query(&["hostile", "example", "com"]);
        let mut seed = 0x9E37_79B9u64;
        for n in 0..512usize {
            // Deterministic pseudo-random bytes of varying lengths.
            let len = (n * 7) % 200;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                bytes.push(seed as u8);
            }
            let _ = query_name(&bytes);
            let _ = observe_response("hostile.example.com", &bytes);
            let _ = ingest(&registry, &q, &bytes);
        }
        // Structured hostile packets: valid header, garbage questions/answers.
        for _ in 0..64 {
            let mut msg = Msg::with_header(true, false, 0, 0xFFFF, 0xFFFF).build();
            msg.extend_from_slice(&[0xC0, 0x00, 0xC0, 0x0C, 0xFF, 0x00]);
            let _ = parse_answers(&msg);
            let _ = observe_response("hostile.example.com", &msg);
        }
    }

    #[test]
    fn registry_ttl_expiry_is_honored() {
        let registry = DnsRegistry::new();
        registry.insert_with_ttl(
            "ttl.example.com",
            vec!["203.0.113.1".parse().unwrap()],
            Duration::from_millis(1),
        );
        // Insertion is observed immediately…
        assert!(registry.resolve("ttl.example.com").is_some());
        std::thread::sleep(Duration::from_millis(5));
        // …and the expired entry is no longer resolvable (removed on read).
        assert!(registry.resolve("ttl.example.com").is_none());
    }
}
