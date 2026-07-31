use async_trait::async_trait;
use balansir_common::{
    Capabilities, DriverId, HealthStatus,
};
use serde::{Deserialize, Serialize};

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
    running: bool,
    health: HealthStatus,
    config_path: Option<String>,
}

impl XrayDriver {
    pub fn new(id: DriverId, config: XrayConfig) -> Self {
        Self {
            id,
            config,
            running: false,
            health: HealthStatus::Unknown,
            config_path: None,
        }
    }

    fn generate_config(&self) -> String {
        // Generate Xray JSON config
        let transport = match &self.config.transport {
            XrayTransport::Tcp => r#""tcp""#,
            XrayTransport::WebSocket { path } => {
                return format!(
                    r#"{{
  "inbounds": [
    {{
      "port": 10808,
      "protocol": "socks",
      "settings": {{ "udp": true }}
    }},
    {{
      "port": 10809,
      "protocol": "http"
    }}
  ],
  "outbounds": [
    {{
      "protocol": "vless",
      "settings": {{
        "vnext": [
          {{
            "address": "{}",
            "port": {},
            "users": [
              {{
                "id": "{}",
                "flow": "{}"
              }}
            ]
          }}
        ]
      }},
      "streamSettings": {{
        "network": "ws",
        "wsSettings": {{
          "path": "{}"
        }},
        "security": "tls",
        "tlsSettings": {{
          "serverName": "{}"
        }}
      }}
    }}
  ]
}}"#,
                    self.config.server,
                    self.config.port,
                    self.config.uuid,
                    self.config.flow.as_deref().unwrap_or(""),
                    path,
                    self.config.tls.as_ref().map(|t| t.server_name.as_str()).unwrap_or("")
                );
            }
            _ => r#""tcp""#,
        };

        format!(
            r#"{{
  "inbounds": [
    {{
      "port": 10808,
      "protocol": "socks",
      "settings": {{ "udp": true }}
    }},
    {{
      "port": 10809,
      "protocol": "http"
    }}
  ],
  "outbounds": [
    {{
      "protocol": "vless",
      "settings": {{
        "vnext": [
          {{
            "address": "{}",
            "port": {},
            "users": [
              {{
                "id": "{}",
                "flow": "{}"
              }}
            ]
          }}
        ]
      }},
      "streamSettings": {{
        "network": {},
        "security": "tls"
      }}
    }}
  ]
}}"#,
            self.config.server,
            self.config.port,
            self.config.uuid,
            self.config.flow.as_deref().unwrap_or(""),
            transport
        )
    }

    fn write_config(&self) -> Result<String, String> {
        let config = self.generate_config();
        let path = format!("/tmp/balansir-xray-{}.json", self.id.as_u32());

        std::fs::write(&path, config)
            .map_err(|e| format!("Failed to write config: {}", e))?;

        Ok(path)
    }

    fn start_process(&self, config_path: &str) -> Result<(), String> {
        // Check if xray binary exists
        let xray_path = which::which("xray")
            .or_else(|_| which::which("xray-core"))
            .map_err(|_| "xray binary not found in PATH")?;

        // Start xray process
        let child = std::process::Command::new(&xray_path)
            .args(["run", "-c", config_path])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to start xray: {}", e))?;

        // Store PID for later cleanup
        // In production, we'd store this in the driver struct
        let _ = child.id();

        Ok(())
    }

    fn stop_process(&self) -> Result<(), String> {
        // Kill xray process by finding it
        let output = std::process::Command::new("pkill")
            .args(["-f", &format!("balansir-xray-{}", self.id.as_u32())])
            .output();

        match output {
            Ok(_) => Ok(()),
            Err(_) => Ok(()), // Process might not exist
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

    async fn start(&mut self) -> Result<(), String> {
        tracing::info!("Starting Xray driver: {}", self.config.server);

        let config_path = self.write_config()?;
        self.start_process(&config_path)?;
        self.config_path = Some(config_path);

        self.running = true;
        self.health = HealthStatus::Healthy;

        tracing::info!("Xray driver started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), String> {
        tracing::info!("Stopping Xray driver");

        self.stop_process()?;

        if let Some(ref path) = self.config_path {
            let _ = std::fs::remove_file(path);
        }

        self.running = false;
        self.health = HealthStatus::Unknown;

        tracing::info!("Xray driver stopped");
        Ok(())
    }

    async fn restart(&mut self) -> Result<(), String> {
        self.stop().await?;
        self.start().await?;
        Ok(())
    }

    async fn health_check(&self) -> HealthStatus {
        if !self.running {
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
    fn test_xray_config() {
        let config = XrayConfig {
            server: "proxy.example.com".to_string(),
            port: 443,
            uuid: "test-uuid".to_string(),
            flow: Some("xtls-rprx-vision".to_string()),
            transport: XrayTransport::WebSocket {
                path: "/ws".to_string(),
            },
            tls: Some(XrayTls {
                server_name: "example.com".to_string(),
                allow_insecure: false,
            }),
        };

        let driver = XrayDriver::new(DriverId::XRAY, config);
        assert_eq!(driver.id(), DriverId::XRAY);
        assert_eq!(driver.name(), "Xray");
        assert!(driver.capabilities().contains(Capabilities::PROXY));
    }

    #[test]
    fn test_xray_config_generation() {
        let config = XrayConfig {
            server: "proxy.example.com".to_string(),
            port: 443,
            uuid: "test-uuid".to_string(),
            flow: Some("xtls-rprx-vision".to_string()),
            transport: XrayTransport::Tcp,
            tls: None,
        };

        let driver = XrayDriver::new(DriverId::XRAY, config);
        let config_str = driver.generate_config();

        assert!(config_str.contains("proxy.example.com"));
        assert!(config_str.contains("443"));
        assert!(config_str.contains("test-uuid"));
    }
}
