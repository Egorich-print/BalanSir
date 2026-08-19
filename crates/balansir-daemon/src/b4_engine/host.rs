//! Host-stack observation source (P7.2, ADR-026).
//!
//! Reads the signals B4 is allowed to use (ADR-024 §4): TCP retransmissions /
//! reset / timeout from the host TCP table, and DNS resolution status from the
//! DNS plane. **Host-stack only** — no MITM, no payload inspection.
//!
//! On Linux, `/proc/net/tcp` and `/proc/net/tcp6` expose per-connection
//! state, retransmit counts and timeouts. The observer aggregates these per
//! path (by destination IP) into a `B4Observation`. On non-Linux platforms no
//! such table is available; the observer honestly returns unknown signals
//! (the engine then degrades to policy-only behavior).

use crate::b4_engine::observe::{B4Observation, B4Observer};

/// Observes host TCP-table signals (Linux) for a path key.
///
/// A path key may be a bare destination IP (e.g. `203.0.113.5`) or a domain;
/// for domains the observer matches the connection's remote address against
/// the domain's resolved addresses (from the shared DNS registry) — matching
/// the hex `:port` form of `/proc/net/tcp` against a domain never matches, so
/// the raw form is decoded to a dotted quad first.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostStackObserver;

#[async_trait::async_trait]
impl B4Observer for HostStackObserver {
    async fn observe(&self, flow_key: &str) -> B4Observation {
        host_stack_observe(flow_key, None).await
    }
}

#[cfg(target_os = "linux")]
async fn host_stack_observe(
    flow_key: &str,
    resolved: Option<&[std::net::IpAddr]>,
) -> B4Observation {
    let tcp = std::fs::read_to_string("/proc/net/tcp").unwrap_or_default();
    let tcp6 = std::fs::read_to_string("/proc/net/tcp6").unwrap_or_default();
    let mut retransmissions: Option<u32> = None;
    let mut reset_or_timeout: Option<bool> = None;

    let matches_key = |ip: std::net::IpAddr| -> bool {
        match resolved {
            Some(addrs) => addrs.contains(&ip),
            None => ip.to_string() == flow_key,
        }
    };

    for (table, ipv6) in [(tcp.as_str(), false), (tcp6.as_str(), true)] {
        // Skip header line.
        for line in table.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            let Some(remote_ip) = remote_ip_str(fields[2], ipv6) else {
                continue;
            };
            if !matches_key(remote_ip) {
                continue;
            }
            // Connection state: 01=ESTABLISHED, 04=CLOSE, 05=CLOSE_WAIT,
            // 06=LAST_ACK, 08=CLOSING, 09=TIME_WAIT. Only "hard" failure
            // states are interference evidence; terminal states (LAST_ACK /
            // CLOSING / TIME_WAIT) are normal teardown and would otherwise
            // produce false Interfered on every closed flow.
            let state = fields[3];
            if state == "04" || state == "05" {
                reset_or_timeout = Some(true);
            }
            // Retransmit count is in the timer fields (fields[4] contains
            // tr:tm->when); approximate: if any queued tx bytes, treat as
            // potential degradation. Precise retransmit parsing is deferred.
            if let Some(retr) = fields.get(6) {
                if let Ok(r) = retr.trim_end_matches(':').parse::<u32>() {
                    retransmissions = Some(retransmissions.unwrap_or(0).max(r));
                }
            }
        }
    }

    B4Observation {
        retransmissions,
        reset_or_timeout,
        ..Default::default()
    }
}

/// Decode a `/proc/net/tcp` remote `HEXIP:HEXPORT` field into an IP address.
///
/// IPv4 is 8 hex chars little-endian; IPv6 is 32 hex chars with reversed
/// group order (4-3-2-1 in the table).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn remote_ip_str(field: &str, ipv6: bool) -> Option<std::net::IpAddr> {
    let hex = field.split(':').next()?;
    if ipv6 {
        if hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
            let group = std::str::from_utf8(chunk).ok()?;
            let v = u32::from_str_radix(group, 16).ok()?;
            bytes[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        // Group order in /proc/net/tcp6 is reversed (4-3-2-1).
        let mut reordered = [0u8; 16];
        for (dst, src) in reordered.chunks_mut(4).zip(bytes.chunks(4).rev()) {
            dst.copy_from_slice(src);
        }
        Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(reordered)))
    } else {
        if hex.len() != 8 {
            return None;
        }
        let v = u32::from_str_radix(hex, 16).ok()?;
        let b = v.to_le_bytes();
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            b[0], b[1], b[2], b[3],
        )))
    }
}

#[cfg(not(target_os = "linux"))]
async fn host_stack_observe(
    _flow_key: &str,
    _resolved: Option<&[std::net::IpAddr]>,
) -> B4Observation {
    // No host TCP table on non-Linux; honest unknown.
    B4Observation::default()
}

/// Combines host TCP-table signals with the DNS plane's resolution status.
///
/// `dns_ok` is `Some(false)` when the domain has no resolved addresses in the
/// DNS registry (resolution failed or not yet observed), `Some(true)` when it
/// has addresses, and `None` when no DNS source is wired.
#[derive(Debug, Clone)]
pub struct CompositeObserver {
    dns: Option<std::sync::Arc<crate::reconciliation::DnsRegistry>>,
}

impl CompositeObserver {
    pub fn new(dns: Option<std::sync::Arc<crate::reconciliation::DnsRegistry>>) -> Self {
        Self { dns }
    }
}

#[async_trait::async_trait]
impl B4Observer for CompositeObserver {
    async fn observe(&self, flow_key: &str) -> B4Observation {
        let resolved: Option<Vec<std::net::IpAddr>> =
            self.dns.as_ref().and_then(|r| r.resolve(flow_key));
        let mut obs = host_stack_observe(flow_key, resolved.as_deref()).await;
        if let Some(registry) = &self.dns {
            obs.dns_ok = Some(registry.resolve(flow_key).is_some());
        }
        obs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconciliation::DnsRegistry;
    use std::sync::Arc;

    #[test]
    fn composite_observes_dns_status() {
        let registry = DnsRegistry::new();
        registry.insert("api.example.com", vec!["203.0.113.5".parse().unwrap()]);
        let observer = CompositeObserver::new(Some(std::sync::Arc::new(registry)));
        let obs = futures_test_observe(&observer, "api.example.com");
        assert_eq!(obs.dns_ok, Some(true));

        let no_dns = CompositeObserver::new(Some(std::sync::Arc::new(DnsRegistry::new())));
        let obs2 = futures_test_observe(&no_dns, "missing.example.com");
        assert_eq!(obs2.dns_ok, Some(false));
    }

    /// P7.2.2 (ADR-028): ONE shared DnsRegistry is the single DNS observation
    /// truth. A change written to the registry is seen identically by the P6
    /// flow compiler (domain → IP compilation) and by the B4 observer (dns_ok)
    /// — there is no way for the two consumers to observe different DNS truth.
    #[test]
    fn shared_registry_is_single_observation_truth() {
        use crate::reconciliation::FlowCompiler;
        use balansir_common::{Action, DesiredRule, FlowCriteria};

        let registry = std::sync::Arc::new(DnsRegistry::new());
        let compiler = FlowCompiler::new((*registry).clone());
        let observer = CompositeObserver::new(Some(Arc::clone(&registry)));

        let rule = DesiredRule {
            id: 7,
            action: Action::Block,
            priority: 100,
            flow: Some(FlowCriteria {
                dst_domain: Some("api.example.com".to_string()),
                ..Default::default()
            }),
        };
        assert!(
            compiler.compile_rule(&rule).is_empty(),
            "P6 sees unresolved domain before observation"
        );
        let before = futures_test_observe(&observer, "api.example.com");
        assert_eq!(before.dns_ok, Some(false));

        registry.insert(
            "api.example.com",
            vec![
                "203.0.113.5".parse().unwrap(),
                "203.0.113.6".parse().unwrap(),
            ],
        );

        let compiled = compiler.compile_rule(&rule);
        assert_eq!(compiled.len(), 2);
        let after = futures_test_observe(&observer, "api.example.com");
        assert_eq!(after.dns_ok, Some(true));

        registry.remove("api.example.com");
        assert!(compiler.compile_rule(&rule).is_empty());
        let removed = futures_test_observe(&observer, "api.example.com");
        assert_eq!(removed.dns_ok, Some(false));
    }

    /// /proc/net/tcp remote fields decode correctly (little-endian IPv4).
    #[test]
    fn proc_net_remote_decodes_ipv4() {
        // 0100007F = 127.0.0.1 little-endian.
        let hex = "0100007F:1F90";
        assert_eq!(
            remote_ip_str(hex, false),
            Some("127.0.0.1".parse().unwrap())
        );
        // 02C6A8C0 LE -> bytes 0xC0 0xA8 0xC6 0x02 -> 192.168.198.2.
        let hex2 = "02C6A8C0:01BB";
        let ip = remote_ip_str(hex2, false).unwrap();
        assert_eq!(ip.to_string(), "192.168.198.2");
    }

    fn futures_test_observe(observer: &CompositeObserver, key: &str) -> B4Observation {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(observer.observe(key))
    }
}
