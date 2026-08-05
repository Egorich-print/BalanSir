use serde::{Deserialize, Serialize};

use super::PacketContext;

/// Maximum recursion depth for matcher evaluation
const MAX_MATCHER_DEPTH: usize = 16;

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
            Self::IpRange { base, mask } => {
                let mask_bits = !((1u32 << (32 - mask)) - 1);
                let base_u32 = u32::from_be_bytes(*base);
                let dst_u32 = u32::from_be_bytes(ctx.dst_ip);
                (base_u32 & mask_bits) == (dst_u32 & mask_bits)
            }
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
    pub fn validate(&self) -> Result<(), String> {
        let depth = self.depth();
        if depth > MAX_MATCHER_DEPTH {
            Err(format!(
                "Matcher depth {} exceeds maximum {}",
                depth, MAX_MATCHER_DEPTH
            ))
        } else {
            Ok(())
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
        let matcher = Matcher::PortRange {
            start: 443,
            end: 444,
        };
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
                            src_ip,
                            dst_ip,
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
                    src_ip: [0; 4],
                    dst_ip: [0; 4],
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
            src_ip: [0; 4],
            dst_ip: [0; 4],
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
