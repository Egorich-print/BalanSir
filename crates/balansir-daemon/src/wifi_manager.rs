//! Wi-Fi manager (mission §3, §4).
//!
//! Owns the Wi-Fi subsystem on the daemon side: it forwards typed `WifiOp`
//! requests to the executor (the only component that talks to
//! `iw`/`wpa_supplicant`), tracks the last scan/status into the shared
//! subsystem snapshot, and exposes a control seam for the API/WebUI.
//!
//! Security model: SSIDs/passwords never reach the daemon log; the executor
//! writes supplicant configs to `/run/balansir/` mode 0600 and wipes them.
//! There is deliberately no vendor/product pinning — any Linux-compatible
//! adapter works through the capability-based interface.

use async_trait::async_trait;
use balansir_common::network::{WifiNetwork, WifiOp, WifiResult};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

use crate::reconciliation::ExecutorClient;

/// Narrow executor view used by the Wi-Fi manager (implemented by the real
/// IPC client and by fakes in tests).
#[async_trait]
pub trait WifiExec: Send + Sync {
    async fn wifi_op(&self, op: &WifiOp) -> Result<WifiResult, String>;
}

#[async_trait]
impl WifiExec for ExecutorClient {
    async fn wifi_op(&self, op: &WifiOp) -> Result<WifiResult, String> {
        self.wifi_op(op).await.map_err(|e| e.to_string())
    }
}

/// Wi-Fi subsystem view (safe for serialization to the WebUI; no secrets).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct WifiSnapshot {
    /// Interfaces that look like Wi-Fi (kind `wlan`/`wifi`).
    pub interfaces: Vec<String>,
    /// Most recent scan results per interface.
    pub networks: Vec<WifiNetwork>,
    /// Current association state per interface: `"connected"` / `"disconnected"`.
    pub states: Vec<(String, String)>,
    pub last_error: Option<String>,
    pub busy: bool,
}

/// The Wi-Fi manager.
pub struct WifiManager {
    exec: Arc<dyn WifiExec>,
    snapshot: Arc<RwLock<WifiSnapshot>>,
}

impl WifiManager {
    pub fn new(exec: Arc<dyn WifiExec>) -> Self {
        Self {
            exec,
            snapshot: Arc::new(RwLock::new(WifiSnapshot::default())),
        }
    }

    pub fn snapshot(&self) -> Arc<RwLock<WifiSnapshot>> {
        Arc::clone(&self.snapshot)
    }

    /// Detect Wi-Fi interfaces from a live interface list (netlink kind).
    pub fn detect_wifi_interfaces(
        interfaces: &[balansir_common::network::InterfaceInfo],
    ) -> Vec<String> {
        interfaces
            .iter()
            .filter(|i| {
                let kind = i.if_type.as_deref().or(i.kind.as_deref());
                matches!(kind, Some(k) if k.contains("wlan") || k == "wifi")
            })
            .map(|i| i.name.clone())
            .collect()
    }

    /// Refresh state for the given Wi-Fi interfaces: run a status probe per
    /// interface and record association state into the snapshot.
    pub async fn refresh(&self, wifi_interfaces: &[String]) {
        let mut snap = self.snapshot.write().await;
        snap.interfaces = wifi_interfaces.to_vec();
        let mut states = Vec::new();
        let mut last_error = None;
        for iface in wifi_interfaces {
            match self
                .exec
                .wifi_op(&WifiOp::Status {
                    interface: iface.clone(),
                })
                .await
            {
                Ok(result) => {
                    let connected = result
                        .networks
                        .iter()
                        .any(|n| n.selected && !n.ssid.is_empty());
                    states.push((
                        iface.clone(),
                        if connected {
                            "connected".to_string()
                        } else {
                            "disconnected".to_string()
                        },
                    ));
                }
                Err(e) => {
                    debug!(iface, "wifi status: {e}");
                    last_error = Some(e);
                    states.push((iface.clone(), "error".to_string()));
                }
            }
        }
        snap.states = states;
        snap.last_error = last_error;
    }

    /// Scan a Wi-Fi interface and store the results.
    pub async fn scan(&self, interface: &str) -> Result<WifiResult, String> {
        {
            let mut snap = self.snapshot.write().await;
            snap.busy = true;
        }
        let op = WifiOp::Scan {
            interface: interface.to_string(),
        };
        let result = self.exec.wifi_op(&op).await;
        match result {
            Ok(r) => {
                self.snapshot.write().await.networks = r.networks.clone();
                self.snapshot.write().await.busy = false;
                Ok(r)
            }
            Err(e) => {
                self.snapshot.write().await.busy = false;
                Err(e)
            }
        }
    }

    /// Connect to a network (open / WPA-PSK / WPA3-SAE / EAP-PEAP).
    pub async fn connect(
        &self,
        interface: &str,
        ssid: &str,
        password: Option<&str>,
        identity: Option<&str>,
        security: Option<&str>,
    ) -> Result<WifiResult, String> {
        {
            let mut snap = self.snapshot.write().await;
            snap.busy = true;
        }
        let result = self
            .exec
            .wifi_op(&WifiOp::Connect {
                interface: interface.to_string(),
                ssid: ssid.to_string(),
                password: password.map(|p| p.to_string()),
                identity: identity.map(|i| i.to_string()),
                security: security.map(|s| s.to_string()),
            })
            .await;
        self.snapshot.write().await.busy = false;
        result
    }

    /// Disconnect from the current network.
    pub async fn disconnect(&self, interface: &str) -> Result<WifiResult, String> {
        {
            let mut snap = self.snapshot.write().await;
            snap.busy = true;
        }
        let result = self
            .exec
            .wifi_op(&WifiOp::Disconnect {
                interface: interface.to_string(),
            })
            .await;
        self.snapshot.write().await.busy = false;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::network::InterfaceInfo;

    fn wifi_iface(name: &str) -> InterfaceInfo {
        InterfaceInfo {
            name: name.into(),
            kind: Some("wlan".into()),
            if_type: Some("wlan".into()),
            ..Default::default()
        }
    }

    #[test]
    fn detects_wlan_interfaces_by_kind() {
        let eth = InterfaceInfo {
            name: "eth0".into(),
            kind: Some("eth".into()),
            if_type: Some("eth".into()),
            ..Default::default()
        };
        let list = vec![eth, wifi_iface("wlan0"), wifi_iface("wlx00e04c680224")];
        let detected = WifiManager::detect_wifi_interfaces(&list);
        assert_eq!(detected, vec!["wlan0", "wlx00e04c680224"]);
    }

    struct FakeWifi {
        result: WifiResult,
    }

    #[async_trait]
    impl WifiExec for FakeWifi {
        async fn wifi_op(&self, _op: &WifiOp) -> Result<WifiResult, String> {
            Ok(self.result.clone())
        }
    }

    #[tokio::test]
    async fn refresh_records_association_state() {
        let fake = Arc::new(FakeWifi {
            result: WifiResult {
                ok: true,
                detail: "connected to home".into(),
                networks: vec![WifiNetwork {
                    ssid: "home".into(),
                    selected: true,
                    ..Default::default()
                }],
            },
        });
        let manager = WifiManager::new(fake);
        manager.refresh(&["wlan0".to_string()]).await;
        let snap = manager.snapshot().read().await.clone();
        assert_eq!(snap.interfaces, vec!["wlan0"]);
        assert_eq!(
            snap.states,
            vec![("wlan0".to_string(), "connected".to_string())]
        );
    }
}
