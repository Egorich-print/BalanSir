//! Gateway mode: static LAN IP, routing, NAT, DNS listener, management firewall.
//!
//! The RPi runs between the provider and the router:
//!
//! ```text
//! [provider] -- WAN interface (USB Ethernet) -- RPi -- LAN interface -- [router]
//! ```
//!
//! Roles are explicit (never autodetection). This module owns the gateway
//! state: it validates the network config, configures the LAN IP, sets up
//! routing/NAT via the executor, and runs the management firewall.

use crate::network_config::NetworkConfig;
use crate::reconciliation::ExecutorClient;
use balansir_common::network::InterfaceInfo;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Gateway state exposed to the API/WebUI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewayState {
    /// Whether gateway mode is active.
    pub enabled: bool,
    /// WAN interface name.
    pub wan_interface: Option<String>,
    /// LAN interface name.
    pub lan_interface: Option<String>,
    /// LAN IP in CIDR notation.
    pub lan_ip: Option<String>,
    /// WAN MAC (explicit or learned).
    pub wan_mac: Option<String>,
    /// Whether MAC cloning is active.
    pub cloning_active: bool,
    /// Whether NAT/masquerade is active.
    pub nat_active: bool,
    /// Management firewall active.
    pub firewall_active: bool,
    /// DNS listener active.
    pub dns_active: bool,
}

/// Gateway manager: owns the gateway state and reconciles it with the executor.
pub struct GatewayManager {
    exec: Arc<ExecutorClient>,
    state: RwLock<GatewayState>,
    config: RwLock<NetworkConfig>,
}

impl GatewayManager {
    pub fn new(exec: Arc<ExecutorClient>) -> Self {
        Self {
            exec,
            state: RwLock::new(GatewayState::default()),
            config: RwLock::new(NetworkConfig::default()),
        }
    }

    /// Load and validate the network config. Fail-closed: returns Err on
    /// invalid roles so the daemon refuses to start in gateway mode.
    pub async fn load_config(&self, interfaces: &[InterfaceInfo]) -> Result<(), String> {
        let cfg = NetworkConfig::load()?;
        cfg.validate(interfaces)?;
        *self.config.write().await = cfg;
        Ok(())
    }

    /// Reconcile the gateway state with the executor. Applies:
    /// - LAN static IP (if configured)
    /// - WAN MAC cloning (if enabled)
    /// - NAT/masquerade on WAN
    /// - Management firewall (allow LAN→RPi, block WAN management)
    pub async fn reconcile(&self, interfaces: &[InterfaceInfo]) -> Result<(), String> {
        let cfg = self.config.read().await.clone();
        let mut state = self.state.write().await;

        if cfg.wan_interface.is_none() && cfg.lan_interface.is_none() {
            state.enabled = false;
            return Ok(());
        }

        state.enabled = true;
        state.wan_interface = cfg.wan_interface.clone();
        state.lan_interface = cfg.lan_interface.clone();
        state.lan_ip = cfg.lan_ip.clone();
        state.wan_mac = cfg.wan_mac.clone();
        state.cloning_active = cfg.cloning_enabled() && cfg.wan_mac.is_some();

        let wan = cfg.wan_interface.as_ref().ok_or("wan_interface required")?;
        let lan = cfg.lan_interface.as_ref().ok_or("lan_interface required")?;

        // 1. Configure LAN static IP if set
        if let Some(lan_ip) = &cfg.lan_ip {
            if let Err(e) = self.exec.set_interface_ip(lan, lan_ip).await {
                warn!("Failed to set LAN IP {lan_ip} on {lan}: {e}");
            } else {
                info!("Set LAN IP {lan_ip} on {lan}");
            }
        }

        // 2. WAN MAC cloning
        if cfg.cloning_enabled() {
            let mac = cfg.wan_mac.as_deref().or_else(|| {
                // Try to learn from LAN peer
                crate::network_config::learn_lan_peer_mac(lan)
            });
            if let Some(mac) = mac {
                if let Err(e) = self.exec.set_mac(wan, mac).await {
                    warn!("Failed to set WAN MAC {mac} on {wan}: {e}");
                } else {
                    info!("Set WAN MAC {mac} on {wan}");
                }
            } else {
                warn!("WAN MAC cloning enabled but no MAC could be determined");
            }
        }

        // 3. NAT/masquerade on WAN
        if let Err(e) = self.exec.enable_nat(wan, "192.168.3.0/24").await {
            warn!("Failed to enable NAT on {wan}: {e}");
        } else {
            state.nat_active = true;
            info!("NAT/masquerade active on {wan}");
        }

        // 4. Enable IP forwarding
        if let Err(e) = self.exec.enable_forwarding().await {
            warn!("Failed to enable IP forwarding: {e}");
        }

        // 5. Management firewall: allow LAN→RPi services, block WAN management
        if let Err(e) = self
            .exec
            .mgmt_firewall(true, true, lan.to_string(), wan.to_string())
            .await
        {
            warn!("Failed to apply management firewall: {e}");
        } else {
            state.firewall_active = true;
            info!("Management firewall applied: LAN allow, WAN block");
        }

        Ok(())
    }

    /// Get the current gateway state.
    pub async fn state(&self) -> GatewayState {
        self.state.read().await.clone()
    }
}