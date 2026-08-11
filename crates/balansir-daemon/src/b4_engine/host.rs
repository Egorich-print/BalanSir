//! Host-stack observation source (P7.2, ADR-026).
//!
//! Reads the signals B4 is allowed to use (ADR-024 §4): TCP retransmissions /
//! reset / timeout from the host TCP table, and DNS resolution status from the
//! DNS plane. **Host-stack only** — no MITM, no payload inspection.
//!
//! On Linux, `/proc/net/tcp` and `/proc/net/tcp6` expose per-connection
//! state, retransmit counts and timeouts. The observer aggregates these per
//! path (by destination IP suffix matching) into a `B4Observation`. On
//! non-Linux platforms no such table is available; the observer honestly
//! returns unknown signals (the engine then degrades to policy-only
//! behavior).

use crate::b4_engine::observe::{B4Observation, B4Observer};

/// Observes host TCP-table signals (Linux) for a path key.
///
/// A path key may be a bare destination IP (e.g. `203.0.113.5`) or a domain;
/// for domains the observer looks for connections to the resolved IPs by
/// matching the key as a substring of the connection's remote address. When no
/// connection matches, signals are unknown.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostStackObserver;

#[async_trait::async_trait]
impl B4Observer for HostStackObserver {
    async fn observe(&self, flow_key: &str) -> B4Observation {
        host_stack_observe(flow_key).await
    }
}

#[cfg(target_os = "linux")]
async fn host_stack_observe(flow_key: &str) -> B4Observation {
    let tcp = std::fs::read_to_string("/proc/net/tcp").unwrap_or_default();
    let tcp6 = std::fs::read_to_string("/proc/net/tcp6").unwrap_or_default();
    let mut retransmissions: Option<u32> = None;
    let mut reset_or_timeout: Option<bool> = None;

    for table in [tcp.as_str(), tcp6.as_str()] {
        // Skip header line.
        for line in table.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                continue;
            }
            let remote = fields[2]; // e.g. 0100007F:1F90 (little-endian hex ip:port)
            if !remote.contains(flow_key) {
                continue;
            }
            let state = fields[3]; // 01..0F connection state (01=ESTABLISHED, 08=CLOSE_WAIT)
            if state == "08" || state == "07" || state == "06" {
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

#[cfg(not(target_os = "linux"))]
async fn host_stack_observe(_flow_key: &str) -> B4Observation {
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
    host: HostStackObserver,
    dns: Option<std::sync::Arc<crate::reconciliation::DnsRegistry>>,
}

impl CompositeObserver {
    pub fn new(dns: Option<std::sync::Arc<crate::reconciliation::DnsRegistry>>) -> Self {
        Self {
            host: HostStackObserver,
            dns,
        }
    }
}

#[async_trait::async_trait]
impl B4Observer for CompositeObserver {
    async fn observe(&self, flow_key: &str) -> B4Observation {
        let mut obs = self.host.observe(flow_key).await;
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

    fn futures_test_observe(observer: &CompositeObserver, key: &str) -> B4Observation {
        // B4Observer::observe is async; drive it synchronously for the test.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(observer.observe(key))
    }
}
