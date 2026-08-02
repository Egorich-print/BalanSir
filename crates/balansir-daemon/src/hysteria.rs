use async_trait::async_trait;
use balansir_common::{
    Capabilities, DriverId, DriverError, HealthStatus,
};
use serde::{Deserialize, Serialize};
use std::process::Child;

use crate::driver::ComponentDriver;

/// Hysteria 2 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2Config {
    /// Server address (host:port)
    pub server: String,
    /// Authentication password
    pub password: String,
    /// Optional obfuscation
    pub obfs: Option<ObfsConfig>,
    /// Bandwidth settings
    pub bandwidth: BandwidthConfig,
    /// Upstream proxy (optional)
    pub up_proxy: Option<String>,
    /// Downstream proxy (optional)
    pub down_proxy: Option<String>,
    /// TLS settings
    pub tls: Option<TlsConfig>,
}

/// Obfuscation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfsConfig {
    /// Obfuscation mode ("salamander")
    pub mode: String,
    /// Obfuscation password
    pub password: String,
}

/// Bandwidth configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthConfig {
    /// Upload bandwidth in Mbps
    pub up_mbps: Option<u32>,
    /// Download bandwidth in Mbps
    pub down_mbps: Option<u32>,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// SNI (Server Name Indication)
    pub sni: Option<String>,
    /// Skip certificate verification (for testing)
    pub insecure: bool,
    /// CA certificate path
    pub ca_path: Option<String>,
}

/// Hysteria 2 driver
pub struct Hysteria2Driver {
    id: DriverId,
    config: Hysteria2Config,
    running: bool,
    health: HealthStatus,
    config_path: Option<String>,
}

impl Hysteria2Driver {
    /// Create a new Hysteria 2 driver
    pub fn new(id: DriverId, config: Hysteria2Config) -> Self {
        Self {
            id,
            config,
            running: false,
            health: HealthStatus::Unknown,
            config_path: None,
        }
    }

    fn generate_config(&self) -> String {
        let obfs_section = if let Some(ref obfs) = self.config.obfs {
            format!(
                r#""obfs": {{
                "type": "{}",
                "password": "{}"
            }},"#,
                obfs.mode, obfs.password
            )
        } else {
            String::new()
        };

        let tls_section = if let Some(ref tls) = self.config.tls {
            let sni = tls.sni.as_deref().unwrap_or("");
            format!(
                r#""tls": {{
                "sni": "{}",
                "insecure": {}
            }},"#,
                sni, tls.insecure
            )
        } else {
            String::new()
        };

        let up_bw = self.config.bandwidth.up_mbps
            .map(|v| format!("{} Mbps", v))
            .unwrap_or_else(|| "obfs".to_string());

        let down_bw = self.config.bandwidth.down_mbps
            .map(|v| format!("{} Mbps", v))
            .unwrap_or_else(|| "obfs".to_string());

        format!(
            r#"{{
  "server": "{}",
  "auth": "{}",
  "obfs": {{
    "type": "salamander",
    "password": "{}"
  }},
  "bandwidth": {{
    "up": "{}",
    "down": "{}"
  }},
  "outbounds": [
    {{
      "name": "proxy",
      "type": "hysteria2",
      "server": "{}",
      "server_port": {},
      "auth": "{}",
      "obfs": {{
        "type": "salamander",
        "password": "{}"
      }},
      "tls": {{
        "sni": "{}",
        "insecure": {}
      }}
    }}
  ],
  "inbounds": [
    {{
      "name": "socks-in",
      "type": "socks",
      "listen": "127.0.0.1",
      "listen_port": 10808
    }},
    {{
      "name": "http-in",
      "type": "http",
      "listen": "127.0.0.1",
      "listen_port": 10809
    }}
  ],
  "route": {{
    "rules": [
      {{
        "outbound": "proxy"
      }}
    ]
  }}
}}"#,
            self.config.server,
            self.config.password,
            self.config.obfs.as_ref().map(|o| o.password.as_str()).unwrap_or(""),
            up_bw,
            down_bw,
            self.config.server.split(':').next().unwrap_or(""),
            self.config.server.split(':').last().unwrap_or("443").parse::<u16>().unwrap_or(443),
            self.config.password,
            self.config.obfs.as_ref().map(|o| o.password.as_str()).unwrap_or(""),
            self.config.tls.as_ref().and_then(|t| t.sni.as_deref()).unwrap_or(""),
            self.config.tls.as_ref().map(|t| t.insecure).unwrap_or(false),
        )
    }

    fn write_config(&self) -> Result<String, DriverError> {
        let config = self.generate_config();
        let path = format!("/tmp/balansir-hysteria-{}.json", self.id.as_u32());

        std::fs::write(&path, config)
            .map_err(|e| DriverError::StartFailed(format!("Failed to write config: {}", e)))?;

        Ok(path)
    }

    fn start_process(&self, config_path: &str) -> Result<(), DriverError> {
        // Check if hysteria binary exists
        let hysteria_path = which::which("hysteria")
            .or_else(|_| which::which("hysteria2"))
            .map_err(|_| DriverError::BinaryNotFound("hysteria".into()))?;

        // Go runtime memory guardrails
        // GOMEMLIMIT: Hard memory limit (triggers GC before OOM)
        // GOGC: Trigger GC more aggressively (30% instead of default 100%)
        let child = std::process::Command::new(&hysteria_path)
            .args(["client", config_path])
            .env("GOMEMLIMIT", "48MiB")
            .env("GOGC", "30")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| DriverError::StartFailed(format!("Failed to start hysteria: {}", e)))?;

        // Store PID for later cleanup
        let _ = child.id();

        Ok(())
    }

    fn stop_process(&self) -> Result<(), DriverError> {
        // Kill hysteria process
        let output = std::process::Command::new("pkill")
            .args(["-f", &format!("balansir-hysteria-{}", self.id.as_u32())])
            .output();

        match output {
            Ok(_) => Ok(()),
            Err(_) => Ok(()), // Process might not exist
        }
    }
}

#[async_trait]
impl ComponentDriver for Hysteria2Driver {
    fn id(&self) -> DriverId {
        self.id
    }

    fn name(&self) -> &str {
        "Hysteria2"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::PROXY
    }

    async fn start(&mut self) -> Result<(), DriverError> {
        tracing::info!("Starting Hysteria2 driver: {}", self.config.server);

        let config_path = self.write_config()?;
        self.start_process(&config_path)?;
        self.config_path = Some(config_path);

        self.running = true;
        self.health = HealthStatus::Healthy;

        tracing::info!("Hysteria2 driver started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), DriverError> {
        tracing::info!("Stopping Hysteria2 driver");

        self.stop_process()?;

        if let Some(ref path) = self.config_path {
            let _ = std::fs::remove_file(path);
        }

        self.running = false;
        self.health = HealthStatus::Unknown;

        tracing::info!("Hysteria2 driver stopped");
        Ok(())
    }

    async fn restart(&mut self) -> Result<(), DriverError> {
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
            .args(["-f", &format!("balansir-hysteria-{}", self.id.as_u32())])
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
    fn test_hysteria2_config() {
        let config = Hysteria2Config {
            server: "proxy.example.com:443".to_string(),
            password: "test-password".to_string(),
            obfs: Some(ObfsConfig {
                mode: "salamander".to_string(),
                password: "obfs-password".to_string(),
            }),
            bandwidth: BandwidthConfig {
                up_mbps: Some(50),
                down_mbps: Some(100),
            },
            up_proxy: None,
            down_proxy: None,
            tls: Some(TlsConfig {
                sni: Some("example.com".to_string()),
                insecure: false,
                ca_path: None,
            }),
        };

        let driver = Hysteria2Driver::new(DriverId::Hysteria, config);
        assert_eq!(driver.id(), DriverId::Hysteria);
        assert_eq!(driver.name(), "Hysteria2");
        assert!(driver.capabilities().contains(Capabilities::PROXY));
    }

    #[test]
    fn test_hysteria2_config_generation() {
        let config = Hysteria2Config {
            server: "proxy.example.com:443".to_string(),
            password: "test-password".to_string(),
            obfs: Some(ObfsConfig {
                mode: "salamander".to_string(),
                password: "obfs-password".to_string(),
            }),
            bandwidth: BandwidthConfig {
                up_mbps: Some(50),
                down_mbps: Some(100),
            },
            up_proxy: None,
            down_proxy: None,
            tls: None,
        };

        let driver = Hysteria2Driver::new(DriverId::Hysteria, config);
        let config_str = driver.generate_config();

        assert!(config_str.contains("proxy.example.com"));
        assert!(config_str.contains("test-password"));
        assert!(config_str.contains("salamander"));
    }
}
