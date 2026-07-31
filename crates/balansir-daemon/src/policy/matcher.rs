use serde::{Deserialize, Serialize};

use super::PacketContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Matcher {
    Any,
    None,
    DomainSuffix { suffix: u32 },
    DomainExact { hash: u32 },
    IpRange { base: [u8; 4], mask: u8 },
    Port { port: u16 },
    PortRange { start: u16, end: u16 },
    Protocol { proto: u8 },
    Interface { id: u32 },
    All(Vec<Matcher>),
    AnyOf(Vec<Matcher>),
    Not(Box<Matcher>),
}

impl Matcher {
    pub fn matches(&self, ctx: &PacketContext) -> bool {
        match self {
            Self::Any => true,
            Self::None => false,
            Self::DomainSuffix { suffix } => {
                ctx.domain_hash.map_or(false, |h| h == *suffix)
            }
            Self::DomainExact { hash } => {
                ctx.domain_hash.map_or(false, |h| h == *hash)
            }
            Self::IpRange { base, mask } => {
                let mask_bits = !((1u32 << (32 - mask)) - 1);
                let base_u32 = u32::from_be_bytes(*base);
                let dst_u32 = u32::from_be_bytes(ctx.dst_ip);
                (base_u32 & mask_bits) == (dst_u32 & mask_bits)
            }
            Self::Port { port } => {
                ctx.dst_port == *port
            }
            Self::PortRange { start, end } => {
                ctx.dst_port >= *start && ctx.dst_port <= *end
            }
            Self::Protocol { proto } => {
                ctx.protocol == *proto
            }
            Self::Interface { id } => {
                ctx.interface.map_or(false, |i| i == *id)
            }
            Self::All(matchers) => {
                matchers.iter().all(|m| m.matches(ctx))
            }
            Self::AnyOf(matchers) => {
                matchers.iter().any(|m| m.matches(ctx))
            }
            Self::Not(inner) => {
                !inner.matches(ctx)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matcher_any() {
        let matcher = Matcher::Any;
        let ctx = PacketContext {
            src_ip: [192, 168, 1, 1],
            dst_ip: [142, 250, 80, 46],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: None,
            interface: None,
        };
        assert!(matcher.matches(&ctx));
    }

    #[test]
    fn test_matcher_port() {
        let matcher = Matcher::Port { port: 443 };
        let ctx = PacketContext {
            src_ip: [192, 168, 1, 1],
            dst_ip: [142, 250, 80, 46],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: None,
            interface: None,
        };
        assert!(matcher.matches(&ctx));
    }

    #[test]
    fn test_matcher_port_range() {
        let matcher = Matcher::PortRange { start: 443, end: 444 };
        let ctx_ok = PacketContext {
            src_ip: [192, 168, 1, 1],
            dst_ip: [142, 250, 80, 46],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: None,
            interface: None,
        };
        let ctx_fail = PacketContext {
            dst_port: 80,
            ..ctx_ok
        };
        assert!(matcher.matches(&ctx_ok));
        assert!(!matcher.matches(&ctx_fail));
    }

    #[test]
    fn test_matcher_all() {
        let matcher = Matcher::All(vec![
            Matcher::Protocol { proto: 6 },
            Matcher::Port { port: 443 },
        ]);
        let ctx = PacketContext {
            src_ip: [192, 168, 1, 1],
            dst_ip: [142, 250, 80, 46],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: None,
            interface: None,
        };
        assert!(matcher.matches(&ctx));
    }

    #[test]
    fn test_matcher_not() {
        let matcher = Matcher::Not(Box::new(Matcher::Port { port: 80 }));
        let ctx = PacketContext {
            src_ip: [192, 168, 1, 1],
            dst_ip: [142, 250, 80, 46],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: None,
            interface: None,
        };
        assert!(matcher.matches(&ctx));
    }
}
