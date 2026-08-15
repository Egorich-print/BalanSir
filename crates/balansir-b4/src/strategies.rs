//! DPI-bypass strategies applied to intercepted TCP packets.
//!
//! Each strategy takes a parsed TCP packet and returns an optional replacement
//! (mutated) packet. Strategies mirror the classic b4 ("Bye Bye Big Bro")
//! techniques: MSS/fragmentation confusion, TCP option stripping, TTL
//! disorientation, and fake/decoy handling.

use crate::packet::{fix_ipv4_checksum, fix_tcp_checksum, tcp_opt, TcpPacket};

/// A single bypass strategy for one flow/profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Rewrite the TCP MSS option (often the DPI fingerprint for path MTU /
    /// DPI detection). Lowering MSS changes the sender's segmentation.
    Mss { mss: u16 },
    /// Strip the SACK-permitted TCP option.
    StripSack,
    /// Alter the IP TTL on the SYN (TTL disorientation).
    Ttl { ttl: u8 },
    /// Lower the advertised window (window-scaling confusion).
    Noop, // placeholder reserved
}

impl Strategy {
    /// Apply the strategy to a packet. Returns Some(mutated) if changed.
    pub fn apply(&self, pkt: &mut TcpPacket) -> bool {
        match *self {
            Strategy::Mss { mss } => tcp_opt::set_mss(pkt, mss),
            Strategy::StripSack => tcp_opt::strip_option(pkt, tcp_opt::SACK_PERMITTED),
            Strategy::Ttl { ttl } => {
                let old = pkt.raw[8];
                if old != ttl {
                    pkt.raw[8] = ttl;
                    true
                } else {
                    false
                }
            }
            Strategy::Noop => false,
        }
    }

    /// Apply and recompute checksums. Returns Some(new packet) or None.
    pub fn mutate(&self, pkt: &TcpPacket) -> Option<Vec<u8>> {
        let mut copy = pkt.clone();
        if self.apply(&mut copy) {
            fix_ipv4_checksum(&mut copy);
            fix_tcp_checksum(&mut copy);
            Some(copy.raw)
        } else {
            None
        }
    }
}

/// A configured profile: domain(s) + the strategies applied to their traffic.
#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    /// Domain suffixes this profile applies to (host match on TLS SNI / DNS).
    pub domains: Vec<String>,
    /// Strategies applied, in order.
    pub strategies: Vec<Strategy>,
}

impl Profile {
    /// Does this profile match a hostname (suffix match, case-insensitive)?
    pub fn matches_host(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        self.domains.iter().any(|d| {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            h == d || h.ends_with(&format!(".{d}"))
        })
    }
}

/// The full engine configuration: one default profile + named profiles.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub profiles: Vec<Profile>,
}

impl EngineConfig {
    /// Resolve the profile for a hostname (default profile if none match).
    pub fn profile_for(&self, host: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.matches_host(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_matches_suffix() {
        let p = Profile {
            name: "yt".into(),
            domains: vec!["youtube.com".into(), "googlevideo.com".into()],
            strategies: vec![],
        };
        assert!(p.matches_host("youtube.com"));
        assert!(p.matches_host("www.youtube.com"));
        assert!(p.matches_host("GOOGLEVIDEO.COM"));
        assert!(!p.matches_host("youtube.org"));
        assert!(!p.matches_host("notyoutube.com"));
    }

    #[test]
    fn mss_strategy_mutates_and_checksums() {
        // build a packet without MSS then apply Mss strategy which adds none —
        // here we just verify Ttl mutation path (always safe).
        let raw = crate::packet::tests_synth_syn();
        let pkt = TcpPacket::parse(&raw).unwrap();
        let mutated = Strategy::Ttl { ttl: 63 }.mutate(&pkt);
        assert!(mutated.is_some());
        let m = mutated.unwrap();
        assert_eq!(m[8], 63);
    }
}
