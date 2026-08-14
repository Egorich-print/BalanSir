use async_trait::async_trait;
use balansir_common::{Capabilities, DriverError, DriverId, HealthStatus};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::process::Child;

use crate::driver::ComponentDriver;

/// Xray configuration (VLESS/XTLS)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayConfig {
    pub server: String,
    pub port: u16,
    #[serde(skip_serializing)]
    pub uuid: SecretString,
    pub flow: Option<String>,
    pub transport: XrayTransport,
    pub tls: Option<XrayTls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XrayTransport {
    Tcp,
    WebSocket { path: String },
    Grpc { service_name: String },
    HttpUpgrade { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayTls {
    pub server_name: String,
    pub allow_insecure: bool,
}

/// Xray process manager
pub struct XrayDriver {
    id: DriverId,
    config: XrayConfig,
    health: HealthStatus,
    config_path: Option<String>,
    child: Option<Child>,
}

impl XrayDriver {
    pub fn new(id: DriverId, config: XrayConfig) -> Self {
        Self {
            id,
            config,
            health: HealthStatus::Unknown,
            config_path: None,
            child: None,
        }
    }

    fn generate_config(&self) -> String {
        use serde_json::json;

        let (network, stream_extra) = match &self.config.transport {
            XrayTransport::Tcp => ("tcp", json!({})),
            XrayTransport::WebSocket { path } => ("ws", json!({ "wsSettings": { "path": path } })),
            XrayTransport::Grpc { service_name } => (
                "grpc",
                json!({ "grpcSettings": { "serviceName": service_name } }),
            ),
            XrayTransport::HttpUpgrade { path } => (
                "httpupgrade",
                json!({ "httpupgradeSettings": { "path": path } }),
            ),
        };

        let tls = match &self.config.tls {
            Some(tls) => json!({
                "security": "tls",
                "tlsSettings": {
                    "serverName": tls.server_name,
                    "allowInsecure": tls.allow_insecure,
                }
            }),
            None => json!({ "security": "none" }),
        };

        let flow = self.config.flow.as_deref().unwrap_or("");

        let mut stream_settings = json!({ "network": network });
        if let Some(extra) = stream_extra.as_object() {
            stream_settings
                .as_object_mut()
                .unwrap()
                .extend(extra.clone());
        }
        if let Some(t) = tls.as_object() {
            stream_settings.as_object_mut().unwrap().extend(t.clone());
        }

        let config = json!({
            "log": { "loglevel": "warning" },
            "inbounds": [
                { "port": 10808, "protocol": "socks", "settings": { "udp": true } },
                { "port": 10809, "protocol": "http" }
            ],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": self.config.server,
                        "port": self.config.port,
                        "users": [{ "id": self.config.uuid.expose_secret(), "flow": flow }]
                    }]
                },
                "streamSettings": stream_settings
            }]
        });
        serde_json::to_string_pretty(&config).unwrap_or_default()
    }

    fn start_process(&mut self, config_path: &str) -> Result<(), DriverError> {
        let xray_path = balansir_common::paths::resolve_bin("xray")
            .or_else(|| balansir_common::paths::resolve_bin("xray-core"))
            .ok_or_else(|| DriverError::BinaryNotFound("xray".into()))?;

        // Go runtime memory guardrails
        // GOMEMLIMIT: Hard memory limit (triggers GC before OOM)
        // GOGC: Trigger GC more aggressively (30% instead of default 100%)
        let child = std::process::Command::new(&xray_path)
            .args(["run", "-c", config_path])
            .env("GOMEMLIMIT", "48MiB")
            .env("GOGC", "30")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| DriverError::StartFailed(format!("Failed to start xray: {}", e)))?;

        self.child = Some(child);
        self.config_path = Some(config_path.to_string());

        Ok(())
    }

    fn stop_process(&mut self) -> Result<(), DriverError> {
        if let Some(mut child) = self.child.take() {
            child
                .kill()
                .map_err(|e| DriverError::StopFailed(format!("Failed to kill xray: {}", e)))?;
            child
                .wait()
                .map_err(|e| DriverError::StopFailed(format!("Failed to wait xray: {}", e)))?;
        }

        if let Some(ref path) = self.config_path {
            let _ = std::fs::remove_file(path);
            self.config_path = None;
        }

        Ok(())
    }
}

/// Probe whether an xray process is currently running (for the WebUI
/// Xray panel). Binary may be absent — that's "not installed", not "failed".
pub fn probe_status() -> serde_json::Value {
    let installed = balansir_common::paths::resolve_bin("xray")
        .or_else(|| balansir_common::paths::resolve_bin("xray-core"))
        .is_some();
    let running = std::process::Command::new("pgrep")
        .args(["-x", "xray"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    serde_json::json!({ "installed": installed, "running": running })
}

impl Drop for XrayDriver {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[async_trait]
impl ComponentDriver for XrayDriver {
    fn id(&self) -> DriverId {
        self.id
    }

    fn name(&self) -> &str {
        "Xray"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::PROXY
    }

    async fn start(&mut self) -> Result<(), DriverError> {
        tracing::info!("Starting Xray driver: {}", self.config.server);

        let config = zeroize::Zeroizing::new(self.generate_config());
        let path =
            crate::secrets::write_secret(&self.id.as_u32().to_string(), "xray", config.as_bytes())?
                .into_os_string()
                .into_string()
                .map_err(|_| DriverError::StartFailed("non-UTF8 secret path".into()))?;
        self.start_process(&path)?;

        self.health = HealthStatus::Healthy;
        tracing::info!("Xray driver started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), DriverError> {
        tracing::info!("Stopping Xray driver");
        self.stop_process()?;
        crate::secrets::remove_secret(&crate::secrets::secret_path(
            &self.id.as_u32().to_string(),
            "xray",
        ));
        self.health = HealthStatus::Unknown;
        tracing::info!("Xray driver stopped");
        Ok(())
    }

    async fn restart(&mut self) -> Result<(), DriverError> {
        self.stop().await?;
        self.start().await?;
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        if self.child.is_none() {
            return HealthStatus::Unhealthy { reason: 1 };
        }

        // Check if process is still running
        let output =
            std::process::Command::new(balansir_common::paths::resolve_bin_or_default("pgrep"))
                .args(["-f", &format!("balansir-xray-{}", self.id.as_u32())])
                .output();

        match output {
            Ok(out) if out.status.success() => HealthStatus::Healthy,
            _ => HealthStatus::Degraded { reason: 1 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn cfg(transport: XrayTransport, tls: Option<XrayTls>) -> XrayConfig {
        XrayConfig {
            server: "vpn.example.com".into(),
            port: 443,
            uuid: SecretString::from("deadbeef-0000-0000-0000-000000000001"),
            flow: Some("xtls-rprx-vision".into()),
            transport,
            tls,
        }
    }

    #[test]
    fn tcp_tls_config() {
        let c = cfg(
            XrayTransport::Tcp,
            Some(XrayTls {
                server_name: "vpn.example.com".into(),
                allow_insecure: false,
            }),
        );
        let json: serde_json::Value =
            serde_json::from_str(&XrayDriver::new(DriverId::Xray, c).generate_config()).unwrap();
        assert_eq!(json["outbounds"][0]["streamSettings"]["network"], "tcp");
        assert_eq!(json["outbounds"][0]["streamSettings"]["security"], "tls");
        assert_eq!(
            json["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"],
            "vpn.example.com"
        );
    }

    #[test]
    fn ws_transport_config() {
        let c = cfg(XrayTransport::WebSocket { path: "/ws".into() }, None);
        let json: serde_json::Value =
            serde_json::from_str(&XrayDriver::new(DriverId::Xray, c).generate_config()).unwrap();
        assert_eq!(json["outbounds"][0]["streamSettings"]["network"], "ws");
        assert_eq!(
            json["outbounds"][0]["streamSettings"]["wsSettings"]["path"],
            "/ws"
        );
        assert_eq!(json["outbounds"][0]["streamSettings"]["security"], "none");
    }

    #[test]
    fn grpc_and_httpupgrade_transports() {
        let g = cfg(
            XrayTransport::Grpc {
                service_name: "svc".into(),
            },
            None,
        );
        let gjson: serde_json::Value =
            serde_json::from_str(&XrayDriver::new(DriverId::Xray, g).generate_config()).unwrap();
        assert_eq!(gjson["outbounds"][0]["streamSettings"]["network"], "grpc");
        assert_eq!(
            gjson["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"],
            "svc"
        );

        let h = cfg(
            XrayTransport::HttpUpgrade {
                path: "/hup".into(),
            },
            None,
        );
        let hjson: serde_json::Value =
            serde_json::from_str(&XrayDriver::new(DriverId::Xray, h).generate_config()).unwrap();
        assert_eq!(
            hjson["outbounds"][0]["streamSettings"]["network"],
            "httpupgrade"
        );
        assert_eq!(
            hjson["outbounds"][0]["streamSettings"]["httpupgradeSettings"]["path"],
            "/hup"
        );
    }

    #[test]
    fn config_contains_uuid_and_flow() {
        let c = cfg(XrayTransport::Tcp, None);
        let json: serde_json::Value =
            serde_json::from_str(&XrayDriver::new(DriverId::Xray, c).generate_config()).unwrap();
        assert_eq!(
            json["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"],
            "deadbeef-0000-0000-0000-000000000001"
        );
        assert_eq!(
            json["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
    }
}
