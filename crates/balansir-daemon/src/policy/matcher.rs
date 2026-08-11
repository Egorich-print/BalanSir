use serde::{Deserialize, Serialize};

use super::error::{PolicyError, PolicyResult};
use super::PacketContext;

/// Maximum recursion depth for matcher evaluation
const MAX_MATCHER_DEPTH: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Matcher {
    Any,
    None,
    DomainSuffix { suffix: u32 },
    DomainExact { hash: u32 },
    IpRange { base: std::net::IpAddr, mask: u8 },
    Port { port: u16 },
    PortRange { start: u16, end: u16 },
    Protocol { proto: u8 },
    Interface { id: u32 },
    All(Vec<Matcher>),
    AnyOf(Vec<Matcher>),
    Not(Box<Matcher>),
}

impl Matcher {
    /// Check if matcher matches the packet context
    pub fn matches(&self, ctx: &PacketContext) -> bool {
        self.matches_inner(ctx, 0)
    }

    /// Internal recursive matching with depth limit
    fn matches_inner(&self, ctx: &PacketContext, depth: usize) -> bool {
        // Prevent stack overflow from deeply nested matchers
        if depth > MAX_MATCHER_DEPTH {
            tracing::warn!("Matcher recursion depth exceeded (>{})", MAX_MATCHER_DEPTH);
            return false;
        }

        match self {
            Self::Any => true,
            Self::None => false,
            Self::DomainSuffix { suffix } => ctx.domain_hash == Some(*suffix),
            Self::DomainExact { hash } => ctx.domain_hash == Some(*hash),
            Self::IpRange { base, mask } => ip_range_matches(*base, *mask, &ctx.dst_ip),
            Self::Port { port } => ctx.dst_port == *port,
            Self::PortRange { start, end } => ctx.dst_port >= *start && ctx.dst_port <= *end,
            Self::Protocol { proto } => ctx.protocol == *proto,
            Self::Interface { id } => ctx.interface == Some(*id),
            Self::All(matchers) => matchers.iter().all(|m| m.matches_inner(ctx, depth + 1)),
            Self::AnyOf(matchers) => matchers.iter().any(|m| m.matches_inner(ctx, depth + 1)),
            Self::Not(inner) => !inner.matches_inner(ctx, depth + 1),
        }
    }

    /// Calculate the depth of nested matchers
    pub fn depth(&self) -> usize {
        match self {
            Self::Any | Self::None => 1,
            Self::DomainSuffix { .. } | Self::DomainExact { .. } => 1,
            Self::IpRange { .. } | Self::Port { .. } | Self::PortRange { .. } => 1,
            Self::Protocol { .. } | Self::Interface { .. } => 1,
            Self::All(matchers) | Self::AnyOf(matchers) => {
                1 + matchers.iter().map(|m| m.depth()).max().unwrap_or(0)
            }
            Self::Not(inner) => 1 + inner.depth(),
        }
    }

    /// Validate matcher doesn't exceed max depth
    pub fn validate(&self) -> PolicyResult<()> {
        let depth = self.depth();
        if depth > MAX_MATCHER_DEPTH {
            Err(PolicyError::MatcherTooDeep {
                depth,
                max: MAX_MATCHER_DEPTH,
            })
        } else {
            Ok(())
        }
    }
}

/// Prefix-match an address against `base/mask` for either address family (A4).
///
/// IPv4 uses a 32-bit mask, IPv6 a 128-bit mask. A family mismatch never
/// matches (an IPv4 base cannot match an IPv6 destination).
fn ip_range_matches(base: std::net::IpAddr, mask: u8, dst: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match (base, dst) {
        (IpAddr::V4(base), IpAddr::V4(dst)) => {
            let mask_bits = if mask >= 32 {
                u32::MAX
            } else {
                !((1u32 << (32 - mask)) - 1)
            };
            (u32::from_be_bytes(base.octets()) & mask_bits)
                == (u32::from_be_bytes(dst.octets()) & mask_bits)
        }
        (IpAddr::V6(base), IpAddr::V6(dst)) => {
            let mask_bits = if mask >= 128 {
                u128::MAX
            } else {
                !((1u128 << (128 - mask)) - 1)
            };
            (u128::from_be_bytes(base.octets()) & mask_bits)
                == (u128::from_be_bytes(dst.octets()) & mask_bits)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matcher_any() {
        let matcher = Matcher::Any;
        let ctx = PacketContext {
            src_ip: std::net::IpAddr::from([192, 168, 1, 1]),
            dst_ip: std::net::IpAddr::from([142, 250, 80, 46]),
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: None,
            interface: None,
        };
        assert!(matcher.matches(&ctx));
    }

    #[test]
    fn test_matcher_ip_range_v4() {
        let matcher = Matcher::IpRange {
            base: std::net::IpAddr::from([192, 168, 1, 0]),
            mask: 24,
        };
        let ctx_ok = PacketContext {
            src_ip: std::net::IpAddr::from([192, 168, 1, 1]),
            dst_ip: std::net::IpAddr::from([192, 168, 1, 200]),
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: None,
            interface: None,
        };
        let ctx_miss = PacketContext {
            dst_ip: std::net::IpAddr::from([192, 168, 2, 1]),
            ..ctx_ok
        };
        assert!(matcher.matches(&ctx_ok));
        assert!(!matcher.matches(&ctx_miss));
    }

    #[test]
    fn test_matcher_ip_range_v6() {
        let matcher = Matcher::IpRange {
            base: std::net::IpAddr::V6("2001:db8::".parse().unwrap()),
            mask: 64,
        };
        let ctx_ok = PacketContext {
            src_ip: std::net::IpAddr::from([192, 168, 1, 1]),
            dst_ip: std::net::IpAddr::V6("2001:db8::1".parse().unwrap()),
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: None,
            interface: None,
        };
        let ctx_miss = PacketContext {
            dst_ip: std::net::IpAddr::V6("2001:db9::1".parse().unwrap()),
            ..ctx_ok
        };
        assert!(matcher.matches(&ctx_ok));
        assert!(!matcher.matches(&ctx_miss));

        // Family mismatch never matches: an IPv4 base cannot match an IPv6 dst.
        let v4_base = Matcher::IpRange {
            base: std::net::IpAddr::from([192, 168, 1, 0]),
            mask: 24,
        };
        assert!(!v4_base.matches(&ctx_ok));
    }

    #[test]
    fn test_matcher_port() {
        let matcher = Matcher::Port { port: 443 };
        let ctx = PacketContext {
            src_ip: std::net::IpAddr::from([192, 168, 1, 1]),
            dst_ip: std::net::IpAddr::from([142, 250, 80, 46]),
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
        let matcher = Matcher::PortRange {
            start: 443,
            end: 444,
        };
        let ctx_ok = PacketContext {
            src_ip: std::net::IpAddr::from([192, 168, 1, 1]),
            dst_ip: std::net::IpAddr::from([142, 250, 80, 46]),
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
            src_ip: std::net::IpAddr::from([192, 168, 1, 1]),
            dst_ip: std::net::IpAddr::from([142, 250, 80, 46]),
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
            src_ip: std::net::IpAddr::from([192, 168, 1, 1]),
            dst_ip: std::net::IpAddr::from([142, 250, 80, 46]),
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            domain_hash: None,
            interface: None,
        };
        assert!(matcher.matches(&ctx));
    }

    // Property-based tests
    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        // Strategy for generating PacketContext
        fn arb_packet_context() -> impl Strategy<Value = PacketContext> {
            (
                any::<[u8; 4]>(),
                any::<[u8; 4]>(),
                any::<u16>(),
                any::<u16>(),
                any::<u8>(),
                proptest::option::of(any::<u32>()),
                proptest::option::of(any::<u32>()),
            )
                .prop_map(
                    |(src_ip, dst_ip, src_port, dst_port, protocol, domain_hash, interface)| {
                        PacketContext {
                            src_ip: std::net::IpAddr::from(src_ip),
                            dst_ip: std::net::IpAddr::from(dst_ip),
                            src_port,
                            dst_port,
                            protocol,
                            domain_hash,
                            interface,
                        }
                    },
                )
        }

        // Property: Not(Not(x)) should be equivalent to x
        proptest! {
            #[test]
            fn double_negation_is_identity(
                port in any::<u16>(),
                ctx in arb_packet_context(),
            ) {
                let matcher = Matcher::Not(Box::new(Matcher::Not(Box::new(Matcher::Port { port }))));
                let direct = Matcher::Port { port };
                prop_assert_eq!(matcher.matches(&ctx), direct.matches(&ctx));
            }
        }

        // Property: Any always matches
        proptest! {
            #[test]
            fn any_always_matches(ctx in arb_packet_context()) {
                let matcher = Matcher::Any;
                prop_assert!(matcher.matches(&ctx));
            }
        }

        // Property: None never matches
        proptest! {
            #[test]
            fn none_never_matches(ctx in arb_packet_context()) {
                let matcher = Matcher::None;
                prop_assert!(!matcher.matches(&ctx));
            }
        }

        // Property: All([]) should match (vacuous truth)
        proptest! {
            #[test]
            fn all_empty_matches(ctx in arb_packet_context()) {
                let matcher = Matcher::All(vec![]);
                prop_assert!(matcher.matches(&ctx));
            }
        }

        // Property: AnyOf([]) should not match
        proptest! {
            #[test]
            fn any_of_empty_not_match(ctx in arb_packet_context()) {
                let matcher = Matcher::AnyOf(vec![]);
                prop_assert!(!matcher.matches(&ctx));
            }
        }

        // Property: Port matcher is exact
        proptest! {
            #[test]
            fn port_matcher_exact(
                port in any::<u16>(),
                dst_port in any::<u16>(),
            ) {
                let matcher = Matcher::Port { port };
                let ctx = PacketContext {
                    src_ip: std::net::IpAddr::from([0, 0, 0, 0]),
                    dst_ip: std::net::IpAddr::from([0, 0, 0, 0]),
                    src_port: 0,
                    dst_port,
                    protocol: 0,
                    domain_hash: None,
                    interface: None,
                };
                prop_assert_eq!(matcher.matches(&ctx), port == dst_port);
            }
        }
    }

    #[test]
    fn test_matcher_depth_limit() {
        // Create deeply nested matcher (should fail validation)
        let mut matcher = Matcher::Port { port: 80 };
        for _ in 0..20 {
            matcher = Matcher::Not(Box::new(matcher));
        }
        assert!(matcher.depth() > 16);
        assert!(matcher.validate().is_err());
    }

    #[test]
    fn test_matcher_recursion_stops() {
        // Create matcher that exceeds depth limit
        let mut matcher = Matcher::Port { port: 80 };
        for _ in 0..20 {
            matcher = Matcher::Not(Box::new(matcher));
        }

        let ctx = PacketContext {
            src_ip: std::net::IpAddr::from([0, 0, 0, 0]),
            dst_ip: std::net::IpAddr::from([0, 0, 0, 0]),
            src_port: 0,
            dst_port: 80,
            protocol: 0,
            domain_hash: None,
            interface: None,
        };

        // Should not panic due to depth limit
        // Result depends on parity of Not nesting
        let _result = matcher.matches(&ctx);
    }
}
