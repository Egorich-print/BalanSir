use async_trait::async_trait;
use balansir_common::{
    Capabilities, DriverId, DriverError, HealthStatus,
};
use serde::{Deserialize, Serialize};

use crate::driver::ComponentDriver;

/// B4 DPI bypass configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct B4Config {
    /// B4 mode: "transparent" or "proxy"
    pub mode: B4Mode,
    /// Ports to intercept
    pub ports: Vec<u16>,
    /// Bypass strategies
    pub strategies: Vec<B4Strategy>,
    /// Upstream proxy (optional)
    pub upstream: Option<String>,
}

/// B4 operation mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum B4Mode {
    /// Transparent mode (via nftables REDIRECT)
    Transparent,
    /// Proxy mode (SOCKS5/HTTP)
    Proxy,
}

/// B4 bypass strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum B4Strategy {
    /// TCP fragmentation
    Fragmentation {
        /// Fragmentation strategy name
        strategy: String,
    },
    /// TTL disorientation
    TtlDisorientation,
    /// Fake packets
    FakePacket {
        /// Sequence number offset
        seq_offset: u32,
    },
    /// Host replacement
    HostReplace {
        /// Original host
        from: String,
        /// Replacement host
        to: String,
    },
}

/// B4 DPI bypass driver
pub struct B4Driver {
    id: DriverId,
    config: B4Config,
    running: bool,
    health: HealthStatus,
}

impl B4Driver {
    /// Create a new B4 driver
    pub fn new(id: DriverId, config: B4Config) -> Self {
        Self {
            id,
            config,
            running: false,
            health: HealthStatus::Unknown,
        }
    }

    fn generate_config(&self) -> String {
        let mode = match self.config.mode {
            B4Mode::Transparent => "transparent",
            B4Mode::Proxy => "proxy",
        };

        let strategies: Vec<String> = self.config.strategies.iter().map(|s| {
            match s {
                B4Strategy::Fragmentation { strategy } => {
                    format!("{{\"type\": \"fragmentation\", \"strategy\": \"{}\"}}", strategy)
                }
                B4Strategy::TtlDisorientation => {
                    "{{\"type\": \"ttl_disorientation\"}}".to_string()
                }
                B4Strategy::FakePacket { seq_offset } => {
                    format!("{{\"type\": \"fake_packet\", \"seq_offset\": {}}}", seq_offset)
                }
                B4Strategy::HostReplace { from, to } => {
                    format!("{{\"type\": \"host_replace\", \"from\": \"{}\", \"to\": \"{}\"}}", from, to)
                }
            }
        }).collect();

        format!(
            r#"{{
  "mode": "{}",
  "ports": [{}],
  "strategies": [{}],
  "upstream": "{}"
}}"#,
            mode,
            self.config.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "),
            strategies.join(", "),
            self.config.upstream.as_deref().unwrap_or(""),
        )
    }

    fn write_config(&self) -> Result<String, DriverError> {
        let config = self.generate_config();
        let path = format!("/tmp/balansir-b4-{}.json", self.id.as_u32());

        std::fs::write(&path, config)
            .map_err(|e| DriverError::StartFailed(format!("Failed to write config: {}", e)))?;

        Ok(path)
    }

    fn start_process(&self, config_path: &str) -> Result<(), DriverError> {
        // Check if b4 binary exists
        let b4_path = which::which("b4")
            .map_err(|_| DriverError::BinaryNotFound("b4".into()))?;

        // Start b4 process
        let child = std::process::Command::new(&b4_path)
            .args(["-c", config_path])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| DriverError::StartFailed(format!("Failed to start b4: {}", e)))?;

        // Store PID for later cleanup
        let _ = child.id();

        Ok(())
    }

    fn stop_process(&self) -> Result<(), DriverError> {
        // Kill b4 process
        let output = std::process::Command::new("pkill")
            .args(["-f", &format!("balansir-b4-{}", self.id.as_u32())])
            .output();

        match output {
            Ok(_) => Ok(()),
            Err(_) => Ok(()), // Process might not exist
        }
    }
}

#[async_trait]
impl ComponentDriver for B4Driver {
    fn id(&self) -> DriverId {
        self.id
    }

    fn name(&self) -> &str {
        "B4"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::PACKET_PROCESSOR
    }

    async fn start(&mut self) -> Result<(), DriverError> {
        tracing::info!("Starting B4 driver");

        let config_path = self.write_config()?;
        self.start_process(&config_path)?;

        self.running = true;
        self.health = HealthStatus::Healthy;

        tracing::info!("B4 driver started");
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), DriverError> {
        tracing::info!("Stopping B4 driver");

        self.stop_process()?;

        self.running = false;
        self.health = HealthStatus::Unknown;

        tracing::info!("B4 driver stopped");
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
            .args(["-f", &format!("balansir-b4-{}", self.id.as_u32())])
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
    fn test_b4_config() {
        let config = B4Config {
            mode: B4Mode::Transparent,
            ports: vec![80, 443],
            strategies: vec![
                B4Strategy::Fragmentation {
                    strategy: "tcp".to_string(),
                },
                B4Strategy::TtlDisorientation,
            ],
            upstream: None,
        };

        let driver = B4Driver::new(DriverId::new(4), config);
        assert_eq!(driver.id(), DriverId::new(4));
        assert_eq!(driver.name(), "B4");
        assert!(driver.capabilities().contains(Capabilities::PACKET_PROCESSOR));
    }

    #[test]
    fn test_b4_config_generation() {
        let config = B4Config {
            mode: B4Mode::Transparent,
            ports: vec![80, 443],
            strategies: vec![
                B4Strategy::Fragmentation {
                    strategy: "tcp".to_string(),
                },
                B4Strategy::FakePacket { seq_offset: 100 },
            ],
            upstream: None,
        };

        let driver = B4Driver::new(DriverId::new(4), config);
        let config_str = driver.generate_config();

        assert!(config_str.contains("transparent"));
        assert!(config_str.contains("80"));
        assert!(config_str.contains("443"));
        assert!(config_str.contains("fragmentation"));
    }
}
