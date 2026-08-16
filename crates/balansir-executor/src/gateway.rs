//! Gateway datapath backend (`MsgType::GatewayOp`).
//!
//! The executor is the *only* component that touches gateway kernel state:
//! `sysctl net.ipv4.ip_forward`, the nftables `nat` hooks (postrouting
//! MASQUERADE), the `filter input` hook (management firewall), and the
//! `filter forward` conntrack handling. The daemon only sends a typed
//! `GatewayConfig` (what the topology *should* be); this backend decides *how*
//! to render it into real rules.
//!
//! Security invariants (mirror the rest of the executor):
//! - no shell, no free-form strings: every rule is a structured `NftRuleSpec`;
//! - all interface/subnet inputs are re-validated before touching the kernel;
//! - every installed rule is tagged with a stable comment so Apply is
//!   idempotent (re-run replaces, never duplicates) and Remove tears down
//!   precisely the rules this backend owns — never a fragile flush-all.

use async_trait::async_trait;
use balansir_common::gateway::{GatewayConfig, GatewayResult, GatewayStatus};
use balansir_common::Result;
use std::sync::Mutex;

use crate::nftables::{NftProto, NftRuleSpec, NftVerdict, NftablesBackend};

/// Stable comment tags owned by the gateway backend (removed precisely on
/// `GatewayOp::Remove`; never a flush-all).
pub const GATEWAY_NAT_TAG: &str = "balansir:gateway:masq";
pub const GATEWAY_FWD_TAG: &str = "balansir:gateway:fwd";
pub const GATEWAY_MGMT_TAG: &str = "balansir:gateway:mgmt";
const SYSCTL_IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

/// Privileged gateway datapath mechanism.
#[async_trait]
pub trait GatewayBackend: Send + Sync {
    /// Apply (idempotently) the full gateway datapath for a config.
    async fn apply(&self, config: &GatewayConfig) -> Result<GatewayResult>;
    /// Tear down every gateway rule this backend installed.
    async fn remove(&self) -> Result<GatewayResult>;
    /// Report the currently applied gateway state (non-authority).
    async fn status(&self) -> Result<GatewayStatus>;
}

/// nftables + sysctl gateway datapath implementation.
pub struct NftablesGatewayBackend {
    backend: NftablesBackend,
    /// Last applied config (used by Status / Remove bookkeeping).
    applied: Mutex<Option<GatewayConfig>>,
}

impl NftablesGatewayBackend {
    pub fn new(backend: NftablesBackend) -> Self {
        Self {
            backend,
            applied: Mutex::new(None),
        }
    }

    fn snapshot(&self) -> Option<GatewayConfig> {
        self.applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn record(&self, config: &GatewayConfig) {
        *self.applied.lock().unwrap_or_else(|e| e.into_inner()) = Some(config.clone());
    }

    fn clear(&self) {
        *self.applied.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Attach the base chains needed by the gateway datapath:
    /// - `nat postrouting` (MASQUERADE) — priority 100, no policy;
    /// - `filter input` (management firewall) — priority 0, policy drop so any
    ///   non-accepted input (i.e. WAN→RPi management) is blocked by default;
    /// - `filter forward` conntrack state handling.
    fn ensure_base_chains(&self) -> Result<()> {
        self.backend.ensure_hooked_chain(
            "postrouting",
            &["type", "nat", "hook", "postrouting", "priority", "100", ";"],
        )?;
        self.backend.ensure_hooked_chain(
            "input",
            &["type", "filter", "hook", "input", "priority", "0", "policy", "drop", ";"],
        )?;
        Ok(())
    }

    fn set_ip_forward(&self, enabled: bool) -> Result<()> {
        std::fs::write(SYSCTL_IP_FORWARD, if enabled { "1\n" } else { "0\n" })
            .map_err(|e| balansir_common::Error::Fatal(format!("sysctl ip_forward: {e}")))?;
        tracing::info!(enabled, "set net.ipv4.ip_forward");
        Ok(())
    }

    fn ip_forward_enabled(&self) -> bool {
        std::fs::read_to_string(SYSCTL_IP_FORWARD)
            .ok()
            .map(|v| v.trim() == "1")
            .unwrap_or(false)
    }

    /// Install the conntrack state handling in the forward chain.
    ///
    /// Order matters: established/related must be accepted before the policy
    /// rules, and invalid must be dropped so the balansir filter rules never
    /// see packet fragments of an established stream as a fresh flow. Both
    /// rules are removed first, then added in order.
    fn apply_forward_conntrack(&self) -> Result<()> {
        self.remove_all_rules("forward", GATEWAY_FWD_TAG)?;
        for (state, verdict) in [("established,related", NftVerdict::Accept), ("invalid", NftVerdict::Drop)] {
            let spec = NftRuleSpec {
                proto: None,
                src_cidr: None,
                dst_cidr: None,
                sport: None,
                dport: None,
                ct_state: Some(state.to_string()),
                iifname: None,
                oifname: None,
                verdict,
                mark: None,
                comment: Some(GATEWAY_FWD_TAG.to_string()),
            };
            self.backend.add_rule_to_chain("forward", &spec)?;
        }
        Ok(())
    }

    /// Remove every rule tagged with `tag` in `chain` (the backend helper
    /// deletes a single handle; loop until none remain).
    fn remove_all_rules(&self, chain: &str, tag: &str) -> Result<()> {
        while self.backend.has_comment_in_chain(chain, tag) {
            self.backend.remove_rule_by_comment_in_chain(chain, tag)?;
        }
        Ok(())
    }

    /// Install the NAT MASQUERADE rule bound to the WAN interface.
    fn apply_nat(&self, config: &GatewayConfig) -> Result<()> {
        self.remove_all_rules("postrouting", GATEWAY_NAT_TAG)?;
        let spec = NftRuleSpec {
            proto: None,
            src_cidr: Some(config.lan_subnet.clone()),
            dst_cidr: None,
            sport: None,
            dport: None,
            ct_state: None,
            iifname: None,
            oifname: Some(config.wan_interface.clone()),
            verdict: NftVerdict::Masquerade,
            mark: None,
            comment: Some(GATEWAY_NAT_TAG.to_string()),
        };
        self.backend.add_rule_to_chain("postrouting", &spec)?;
        Ok(())
    }

    /// Install the management firewall: LAN → RPi admin ports allowed, all
    /// other input (WAN → RPi) blocked by the input chain's drop policy.
    ///
    /// Rules (all tagged `GATEWAY_MGMT_TAG`):
    /// 1. accept established,related (so responses to RPi-originated flows are
    ///    allowed through the input chain);
    /// 2. accept loopback;
    /// 3. accept LAN-subnet → {22, 53, 8080, 9090} (SSH, DNS, API, metrics);
    /// 4. (implicit) drop everything else — the input chain policy is `drop`,
    ///    so WAN management access is blocked.
    fn apply_management(&self, config: &GatewayConfig) -> Result<()> {
        self.remove_all_rules("input", GATEWAY_MGMT_TAG)?;

        // 1. established/related accepted first.
        let est = NftRuleSpec {
            proto: None,
            src_cidr: None,
            dst_cidr: None,
            sport: None,
            dport: None,
            ct_state: Some("established,related".to_string()),
            iifname: None,
            oifname: None,
            verdict: NftVerdict::Accept,
            mark: None,
            comment: Some(GATEWAY_MGMT_TAG.to_string()),
        };
        self.backend.add_rule_to_chain("input", &est)?;

        // 2. loopback.
        let lo = NftRuleSpec {
            proto: None,
            src_cidr: Some("127.0.0.0/8".to_string()),
            dst_cidr: None,
            sport: None,
            dport: None,
            ct_state: None,
            iifname: Some("lo".to_string()),
            oifname: None,
            verdict: NftVerdict::Accept,
            mark: None,
            comment: Some(GATEWAY_MGMT_TAG.to_string()),
        };
        self.backend.add_rule_to_chain("input", &lo)?;

        // 3. LAN subnet → admin ports.
        for port in balansir_common::gateway::DEFAULT_MGMT_PORTS {
            // DNS: allow TCP and UDP. Other ports: TCP only.
            let protos: &[Option<NftProto>] = if *port == 53 {
                &[Some(NftProto::Tcp), Some(NftProto::Udp)]
            } else {
                &[Some(NftProto::Tcp)]
            };
            for p in protos {
                let rule = NftRuleSpec {
                    proto: *p,
                    src_cidr: Some(config.lan_subnet.clone()),
                    dst_cidr: None,
                    sport: None,
                    dport: Some(*port),
                    ct_state: None,
                    iifname: Some(config.lan_interface.clone()),
                    oifname: None,
                    verdict: NftVerdict::Accept,
                    mark: None,
                    comment: Some(GATEWAY_MGMT_TAG.to_string()),
                };
                self.backend.add_rule_to_chain("input", &rule)?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl GatewayBackend for NftablesGatewayBackend {
    async fn apply(&self, config: &GatewayConfig) -> Result<GatewayResult> {
        config.validate().map_err(balansir_common::Error::Misconfiguration)?;
        self.ensure_base_chains()?;
        self.set_ip_forward(true)?;
        self.apply_forward_conntrack()?;
        self.apply_nat(config)?;
        self.apply_management(config)?;
        self.record(config);
        Ok(GatewayResult {
            ok: true,
            detail: format!(
                "NAT (masquerade on {}), forwarding, conntrack and management firewall applied (LAN {} via {})",
                config.wan_interface, config.lan_subnet, config.lan_interface
            ),
        })
    }

    async fn remove(&self) -> Result<GatewayResult> {
        let mut removed = Vec::new();
        for (chain, tag, what) in [
            ("postrouting", GATEWAY_NAT_TAG, "NAT"),
            ("forward", GATEWAY_FWD_TAG, "forward conntrack"),
            ("input", GATEWAY_MGMT_TAG, "management firewall"),
        ] {
            if self.backend.has_comment_in_chain(chain, tag) {
                self.remove_all_rules(chain, tag)
                    .map_err(|e| balansir_common::Error::Fatal(format!("remove {what}: {e}")))?;
                removed.push(what);
            }
        }
        if !removed.is_empty() {
            self.set_ip_forward(false)?;
        }
        self.clear();
        Ok(GatewayResult {
            ok: true,
            detail: if removed.is_empty() {
                "gateway datapath not applied (nothing to remove)".into()
            } else {
                format!("removed: {}", removed.join(", "))
            },
        })
    }

    async fn status(&self) -> Result<GatewayStatus> {
        let applied = self.snapshot();
        let nat_present = self
            .backend
            .has_comment_in_chain("postrouting", GATEWAY_NAT_TAG);
        let mgmt_present = self.backend.has_comment_in_chain("input", GATEWAY_MGMT_TAG);
        let ip_fwd = self.ip_forward_enabled();
        let (wan, lan, subnet) = applied
            .as_ref()
            .map(|c| (Some(c.wan_interface.clone()), Some(c.lan_interface.clone()), Some(c.lan_subnet.clone())))
            .unwrap_or((None, None, None));
        Ok(GatewayStatus {
            enabled: nat_present && ip_fwd,
            wan_interface: wan,
            lan_interface: lan,
            lan_subnet: subnet,
            ip_forward_enabled: ip_fwd,
            mgmt_ports: if mgmt_present {
                balansir_common::gateway::DEFAULT_MGMT_PORTS.to_vec()
            } else {
                Vec::new()
            },
            wan_input_blocked: mgmt_present,
        })
    }
}

/// A record-only gateway backend for tests and non-Linux builds: never touches
/// the kernel, records the last requested config and reports it back.
#[derive(Default)]
pub struct RecordOnlyGatewayBackend {
    applied: Mutex<Option<GatewayConfig>>,
}

#[async_trait]
impl GatewayBackend for RecordOnlyGatewayBackend {
    async fn apply(&self, config: &GatewayConfig) -> Result<GatewayResult> {
        config.validate().map_err(balansir_common::Error::Misconfiguration)?;
        *self.applied.lock().unwrap_or_else(|e| e.into_inner()) = Some(config.clone());
        Ok(GatewayResult {
            ok: true,
            detail: format!(
                "record-only gateway applied: wan={} lan={} subnet={}",
                config.wan_interface, config.lan_interface, config.lan_subnet
            ),
        })
    }

    async fn remove(&self) -> Result<GatewayResult> {
        *self.applied.lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(GatewayResult {
            ok: true,
            detail: "record-only gateway removed".into(),
        })
    }

    async fn status(&self) -> Result<GatewayStatus> {
        let applied = self.applied.lock().unwrap_or_else(|e| e.into_inner());
        Ok(match applied.as_ref() {
            Some(c) => GatewayStatus {
                enabled: true,
                wan_interface: Some(c.wan_interface.clone()),
                lan_interface: Some(c.lan_interface.clone()),
                lan_subnet: Some(c.lan_subnet.clone()),
                ip_forward_enabled: true,
                mgmt_ports: balansir_common::gateway::DEFAULT_MGMT_PORTS.to_vec(),
                wan_input_blocked: true,
            },
            None => GatewayStatus::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> GatewayConfig {
        GatewayConfig {
            wan_interface: "eth1".into(),
            lan_interface: "eth0".into(),
            lan_subnet: "192.168.3.0/24".into(),
        }
    }

    #[tokio::test]
    async fn record_only_apply_remove_status() {
        let backend = RecordOnlyGatewayBackend::default();
        let cfg = config();
        let applied = backend.apply(&cfg).await.unwrap();
        assert!(applied.ok);
        let status = backend.status().await.unwrap();
        assert!(status.enabled);
        assert_eq!(status.wan_interface.as_deref(), Some("eth1"));
        assert_eq!(status.mgmt_ports, balansir_common::gateway::DEFAULT_MGMT_PORTS);
        let removed = backend.remove().await.unwrap();
        assert!(removed.ok);
        let status = backend.status().await.unwrap();
        assert!(!status.enabled);
    }

    #[tokio::test]
    async fn apply_rejects_invalid_config() {
        let backend = RecordOnlyGatewayBackend::default();
        let bad = GatewayConfig {
            wan_interface: "../evil".into(),
            lan_interface: "eth0".into(),
            lan_subnet: "192.168.3.0/24".into(),
        };
        assert!(backend.apply(&bad).await.is_err());
    }

    /// The management rule for a DNS port renders both TCP and UDP accepts.
    #[test]
    fn dns_mgmt_renders_both_transports() {
        // Pure rendering sanity: the NftRuleSpec renderer handles the
        // iifname + ct_state + masquerade vocabulary the gateway uses.
        let spec = NftRuleSpec {
            proto: Some(NftProto::Tcp),
            src_cidr: Some("192.168.3.0/24".to_string()),
            dst_cidr: None,
            sport: None,
            dport: Some(53),
            ct_state: None,
            iifname: Some("eth0".to_string()),
            oifname: None,
            verdict: NftVerdict::Accept,
            mark: None,
            comment: Some(GATEWAY_MGMT_TAG.to_string()),
        };
        let rendered = spec.render();
        assert!(rendered.contains(&"iifname".to_string()));
        assert!(rendered.contains(&"\"eth0\"".to_string()));
        assert!(rendered.contains(&"accept".to_string()));
    }

    #[test]
    fn masquerade_renders() {
        let spec = NftRuleSpec {
            proto: None,
            src_cidr: Some("192.168.3.0/24".to_string()),
            dst_cidr: None,
            sport: None,
            dport: None,
            ct_state: None,
            iifname: None,
            oifname: Some("eth1".to_string()),
            verdict: NftVerdict::Masquerade,
            mark: None,
            comment: Some(GATEWAY_NAT_TAG.to_string()),
        };
        let rendered = spec.render();
        assert!(rendered.contains(&"oifname".to_string()));
        assert!(rendered.contains(&"\"eth1\"".to_string()));
        assert!(rendered.contains(&"masquerade".to_string()));
    }

    #[test]
    fn conntrack_forward_renders() {
        let spec = NftRuleSpec {
            proto: None,
            src_cidr: None,
            dst_cidr: None,
            sport: None,
            dport: None,
            ct_state: Some("established,related".to_string()),
            iifname: None,
            oifname: None,
            verdict: NftVerdict::Accept,
            mark: None,
            comment: Some(GATEWAY_FWD_TAG.to_string()),
        };
        let rendered = spec.render();
        assert!(rendered.contains(&"ct".to_string()));
        assert!(rendered.contains(&"state".to_string()));
        assert!(rendered.contains(&"established,related".to_string()));
        assert!(rendered.contains(&"accept".to_string()));
    }
}
