use async_trait::async_trait;
use balansir_common::{
    Capabilities, DriverId, DriverError, HealthStatus,
};
use serde::{Deserialize, Serialize};
use std::process::Child;

use crate::driver::ComponentDriver;

/// Xray configuration (VLESS/XTLS)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayConfig {
    pub server: String,
    pub port: u16,
    pub uuid: String,
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
        // ... existing config generation code ...
        format!(
            r#"{{
  "inbounds": [
    {{ "port": 10808, "protocol": "socks", "settings": {{ "udp": true }} }},
    {{ "port": 10809, "protocol": "http" }}
  ],
  "outbounds": [{{
    "protocol": "vless",
    "settings": {{ "vnext": [{{ "address": "{}", "port": {}, "users": [{{ "id": "{}", "flow": "{}" }}] }}] }},
    "streamSettings": {{ "network": "tcp", "security": "tls" }}
  }}]
}}"#,
            self.config.server,
            self.config.port,
            self.config.uuid,
            self.config.flow.as_deref().unwrap_or("")
        )
    }

    fn start_process(&mut self, config_path: &str) -> Result<(), DriverError> {
        let xray_path = which::which("xray")
            .or_else(|_| which::which("xray-core"))
            .map_err(|_| DriverError::BinaryNotFound("xray".into()))?;

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
            child.kill().map_err(|e| DriverError::StopFailed(format!("Failed to kill xray: {}", e)))?;
            child.wait().map_err(|e| DriverError::StopFailed(format!("Failed to wait xray: {}", e)))?;
        }

        if let Some(ref path) = self.config_path {
            let _ = std::fs::remove_file(path);
            self.config_path = None;
        }

        Ok(())
    }
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

        let config_path = self.generate_config();
        let path = format!("/tmp/balansir-xray-{}.json", self.id.as_u32());
        std::fs::write(&path, &config_path)
            .map_err(|e| DriverError::StartFailed(format!("Failed to write config: {}", e)))?;

        self.start_process(&path)?;

        self.health = HealthStatus::Healthy;
        tracing::info!("Xray driver started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), DriverError> {
        tracing::info!("Stopping Xray driver");
        self.stop_process()?;
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
        let output = std::process::Command::new("pgrep")
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

    #[test]
    fn test_xray_driver_creation() {
        let config = XrayConfig {
            server: "proxy.example.com".to_string(),
            port: 443,
            uuid: "test-uuid".to_string(),
            flow: Some("xtls-rprx-vision".to_string()),
            transport: XrayTransport::Tcp,
            tls: None,
        };

        let driver = XrayDriver::new(DriverId::XRAY, config);
        assert_eq!(driver.id(), DriverId::XRAY);
        assert!(driver.child.is_none());
    }
}
