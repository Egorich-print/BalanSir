//! Per-path MTU state (P7.2, ADR-026).
//!
//! The executor owns the *applied* path-MTU state and reports it to the daemon
//! (like the rule inventory). MTU is deliberately **per-path**, never a global
//! interface setting (ADR-024 §6). A `PathMtuApplier` is the privileged hook
//! that actually changes the host (e.g. route-level MTU / MSS); the store
//! keeps the authoritative applied set so the daemon can reconcile.

use balansir_common::PathMtu;
use std::collections::HashMap;

/// Privileged hook that applies/removes a per-path MTU on the host.
///
/// The store records state; the applier is what touches the kernel. In tests
/// and on non-privileged builds this is a no-op record-only applier; the real
/// Linux implementation would set route-level MTU/MSS for the path.
#[async_trait::async_trait]
pub trait PathMtuApplier: Send + Sync {
    /// Apply a per-path MTU.
    async fn apply(&self, path: &str, mtu: u16) -> Result<(), String>;
    /// Remove a per-path MTU (restore default).
    async fn restore(&self, path: &str) -> Result<(), String>;
}

/// Record-only applier: tracks intent but performs no host change. Used when
/// no privileged mechanism is wired, so the executor honestly reports the
/// requested state without pretending a kernel change happened.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecordOnlyApplier;

#[async_trait::async_trait]
impl PathMtuApplier for RecordOnlyApplier {
    async fn apply(&self, _path: &str, _mtu: u16) -> Result<(), String> {
        Ok(())
    }
    async fn restore(&self, _path: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Real route-level MTU applier (B4, ADR-026).
///
/// Mechanism: resolve the path to a concrete /32 route via `ip route get`,
/// then pin a host route with `ip route replace <path>/32 via <gw> dev <dev>
/// mtu <mtu>`. Restore deletes the pinned route. Requires `iproute2` (`ip`)
/// and CAP_NET_ADMIN — exactly the executor's privilege domain. If `ip` is
/// missing we fail loudly (never silently claim success).
pub struct RouteMtuApplier;

#[async_trait::async_trait]
impl PathMtuApplier for RouteMtuApplier {
    async fn apply(&self, path: &str, mtu: u16) -> Result<(), String> {
        let Some(route) = current_route_for(path).await else {
            return Err(format!("no route to {path} (cannot pin MTU)"));
        };
        run_ip(&[
            "route",
            "replace",
            &format!("{path}/32"),
            "via",
            &route.gateway,
            "dev",
            &route.device,
            "mtu",
            &mtu.to_string(),
        ])
    }
    async fn restore(&self, path: &str) -> Result<(), String> {
        run_ip(&["route", "del", &format!("{path}/32")])
    }
}

#[derive(Debug, Clone)]
struct RouteInfo {
    gateway: String,
    device: String,
}

/// Resolve `ip route get <path>` into the nexthop gateway + device.
async fn current_route_for(path: &str) -> Option<RouteInfo> {
    let bin = balansir_common::paths::resolve_bin("ip")?;
    let out = std::process::Command::new(&bin)
        .args(["route", "get", path])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // Example: "100.64.0.1 dev wg0 src 100.64.0.2 uid 0" or
    //          "203.0.113.5 via 192.168.1.1 dev eth0 src ..."
    parse_route_line(&text)
}

fn parse_route_line(text: &str) -> Option<RouteInfo> {
    let first = text.lines().next()?;
    let mut gateway = None;
    let mut device = None;
    let mut words = first.split_whitespace();
    let _target = words.next()?;
    while let Some(w) = words.next() {
        match w {
            "via" => gateway = words.next().map(String::from),
            "dev" => device = words.next().map(String::from),
            _ => {}
        }
    }
    // Fall back to "dev" when no gateway (on-link).
    let gateway = gateway.unwrap_or_else(|| {
        device
            .as_deref()
            .map(|_| "onlink".to_string())
            .unwrap_or_default()
    });
    Some(RouteInfo {
        gateway,
        device: device?,
    })
}

fn run_ip(args: &[&str]) -> Result<(), String> {
    let bin = balansir_common::paths::resolve_bin("ip")
        .ok_or_else(|| "ip binary not found".to_string())?;
    let out = std::process::Command::new(&bin)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run ip: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// The executor's applied per-path MTU state, keyed by path.
pub struct PathMtuStore {
    applied: std::sync::Mutex<HashMap<String, u16>>,
    applier: Box<dyn PathMtuApplier>,
}

impl PathMtuStore {
    pub fn new(applier: Box<dyn PathMtuApplier>) -> Self {
        Self {
            applied: std::sync::Mutex::new(HashMap::new()),
            applier,
        }
    }

    /// Apply (or update) a per-path MTU. On applier failure the in-memory state
    /// is left unchanged so the daemon can retry — no partial accounting.
    pub async fn set(&self, path: &str, mtu: u16) -> Result<(), String> {
        self.applier.apply(path, mtu).await?;
        self.applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(path.to_string(), mtu);
        Ok(())
    }

    /// Remove a per-path MTU (rollback). Returns Ok whether or not it was set.
    pub async fn restore(&self, path: &str) -> Result<(), String> {
        self.applier.restore(path).await?;
        self.applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(path);
        Ok(())
    }

    /// The currently applied path-MTU set (non-authority, for reconciliation).
    pub fn state(&self) -> Vec<PathMtu> {
        self.applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(path, mtu)| PathMtu {
                path: path.clone(),
                mtu: *mtu,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_restore_state_roundtrip() {
        let store = PathMtuStore::new(Box::new(RecordOnlyApplier));
        assert!(store.state().is_empty());

        store.set("example.com", 1400).await.unwrap();
        assert_eq!(
            store.state(),
            vec![PathMtu {
                path: "example.com".into(),
                mtu: 1400
            }]
        );

        // Update same path.
        store.set("example.com", 1380).await.unwrap();
        assert_eq!(store.state().len(), 1);
        assert_eq!(store.state()[0].mtu, 1380);

        // Restore removes it.
        store.restore("example.com").await.unwrap();
        assert!(store.state().is_empty());
    }

    #[tokio::test]
    async fn failed_applier_does_not_record() {
        struct Failing;
        #[async_trait::async_trait]
        impl PathMtuApplier for Failing {
            async fn apply(&self, _p: &str, _m: u16) -> Result<(), String> {
                Err("denied".into())
            }
            async fn restore(&self, _p: &str) -> Result<(), String> {
                Ok(())
            }
        }
        let store = PathMtuStore::new(Box::new(Failing));
        assert!(store.set("x.com", 1300).await.is_err());
        assert!(store.state().is_empty());
    }

    #[test]
    fn parses_route_with_gateway() {
        let r = parse_route_line("203.0.113.5 via 192.168.1.1 dev eth0 src 192.168.1.10 uid 0")
            .unwrap();
        assert_eq!(r.gateway, "192.168.1.1");
        assert_eq!(r.device, "eth0");
    }

    #[test]
    fn parses_onlink_route() {
        let r = parse_route_line("100.64.0.1 dev wg0 src 100.64.0.2 uid 0").unwrap();
        assert_eq!(r.device, "wg0");
        assert_eq!(r.gateway, "onlink");
    }

    #[test]
    fn rejects_missing_device() {
        assert!(parse_route_line("203.0.113.5 via 192.168.1.1").is_none());
    }
}
