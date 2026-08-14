use async_trait::async_trait;
use balansir_common::{Capabilities, DriverError, DriverId, HealthStatus};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::process::Child;

use crate::driver::ComponentDriver;

/// Xray configuration (VLESS/XTLS)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayConfig {
    /// Endpoint address (domain or IP).
    pub server: String,
    pub port: u16,
    #[serde(skip_serializing)]
    pub uuid: SecretString,
    pub flow: Option<String>,
    pub transport: XrayTransport,
    pub tls: Option<XrayTls>,
    /// Optional profile/endpoint label (management plane).
    #[serde(default)]
    pub name: Option<String>,
    /// Local SOCKS5 inbound port (default 10808).
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    /// Local HTTP inbound port (default 10809).
    #[serde(default = "default_http_port")]
    pub http_port: u16,
}

const fn default_socks_port() -> u16 {
    10808
}
const fn default_http_port() -> u16 {
    10809
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum XrayTransport {
    #[default]
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

impl XrayConfig {
    /// Validate the endpoint definition. Never trusts raw input: server must
    /// be a plausible host/IP, ports must be in range, WS/HTTPUpgrade paths
    /// must start with `/`.
    pub fn validate(&self) -> Result<(), DriverError> {
        if self.server.trim().is_empty() || self.server.len() > 253 {
            return Err(DriverError::ConfigInvalid(
                "xray server address missing or too long".into(),
            ));
        }
        if self.port == 0 || self.socks_port == 0 || self.http_port == 0 {
            return Err(DriverError::ConfigInvalid(
                "xray ports must be non-zero".into(),
            ));
        }
        if self.socks_port == self.http_port {
            return Err(DriverError::ConfigInvalid(
                "xray socks and http inbound ports must differ".into(),
            ));
        }
        match &self.transport {
            XrayTransport::WebSocket { path } | XrayTransport::HttpUpgrade { path } => {
                if !path.starts_with('/') {
                    return Err(DriverError::ConfigInvalid(format!(
                        "xray transport path {path:?} must start with '/'"
                    )));
                }
            }
            XrayTransport::Grpc { service_name } => {
                if service_name.trim().is_empty() {
                    return Err(DriverError::ConfigInvalid(
                        "xray grpc service_name must not be empty".into(),
                    ));
                }
            }
            XrayTransport::Tcp => {}
        }
        if let Some(tls) = &self.tls {
            if tls.server_name.trim().is_empty() {
                return Err(DriverError::ConfigInvalid(
                    "xray tls server_name must not be empty".into(),
                ));
            }
        }
        Ok(())
    }

    /// A local SOCKS5 endpoint the driver can be probed on.
    pub fn socks_socket_addr(&self) -> std::net::SocketAddr {
        format!("127.0.0.1:{}", self.socks_port)
            .parse()
            .unwrap_or_else(|_| std::net::SocketAddr::from(([127, 0, 0, 1], 10808)))
    }
}

/// The xray `network` value for a transport.
fn transport_network(config: &XrayConfig) -> &'static str {
    match &config.transport {
        XrayTransport::Tcp => "tcp",
        XrayTransport::WebSocket { .. } => "ws",
        XrayTransport::Grpc { .. } => "grpc",
        XrayTransport::HttpUpgrade { .. } => "httpupgrade",
    }
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

    /// Generate a complete, valid Xray runtime config for the endpoint.
    /// Honors the configured transport, TLS parameters, flow, and local
    /// inbound ports. Built with `serde_json` so the output is always valid
    /// JSON (no string-interpolation injection from config values).
    fn generate_config(&self) -> String {
        let cfg = &self.config;

        let mut stream = serde_json::Map::new();
        stream.insert("network".into(), serde_json::json!(transport_network(cfg)));
        let (security, tls_settings) = match &cfg.tls {
            Some(tls) => {
                let mut settings = serde_json::Map::new();
                settings.insert("serverName".into(), serde_json::json!(tls.server_name));
                settings.insert(
                    "allowInsecure".into(),
                    serde_json::json!(tls.allow_insecure),
                );
                ("tls", Some(settings))
            }
            None => ("none", None),
        };
        stream.insert("security".into(), serde_json::json!(security));
        if let Some(settings) = tls_settings {
            stream.insert("tlsSettings".into(), serde_json::Value::Object(settings));
        }
        match &cfg.transport {
            XrayTransport::WebSocket { path } => {
                stream.insert(
                    "wsSettings".into(),
                    serde_json::json!({ "path": path }),
                );
            }
            XrayTransport::Grpc { service_name } => {
                stream.insert(
                    "grpcSettings".into(),
                    serde_json::json!({ "serviceName": service_name }),
                );
            }
            XrayTransport::HttpUpgrade { path } => {
                stream.insert(
                    "httpupgradeSettings".into(),
                    serde_json::json!({ "path": path }),
                );
            }
            XrayTransport::Tcp => {}
        }

        let mut user = serde_json::Map::new();
        user.insert("id".into(), serde_json::json!(cfg.uuid.expose_secret()));
        if let Some(flow) = &cfg.flow {
            if !flow.is_empty() {
                user.insert("flow".into(), serde_json::json!(flow));
            }
        }

        let config = serde_json::json!({
            "log": { "loglevel": "warning" },
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": cfg.socks_port,
                    "protocol": "socks",
                    "settings": { "udp": true }
                },
                {
                    "listen": "127.0.0.1",
                    "port": cfg.http_port,
                    "protocol": "http"
                }
            ],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": cfg.server,
                        "port": cfg.port,
                        "users": [ serde_json::Value::Object(user) ]
                    }]
                },
                "streamSettings": serde_json::Value::Object(stream)
            }],
            "dns": { "queryStrategy": "UseIP" }
        });
        serde_json::to_string_pretty(&config)
            .unwrap_or_else(|_| "{\"log\":{},\"inbounds\":[],\"outbounds\":[]}".into())
    }

    /// The local SOCKS5 endpoint of the running driver.
    pub fn socks_endpoint(&self) -> std::net::SocketAddr {
        self.config.socks_socket_addr()
    }

    /// Label of this endpoint (profile name), when set.
    pub fn label(&self) -> &str {
        self.config
            .name
            .as_deref()
            .unwrap_or(self.config.server.as_str())
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
        self.config.validate()?;
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
        // 1. The process must be alive. `kill(pid, 0)` is a liveness probe
        //    that needs no mutable handle to the Child.
        let alive = match &self.child {
            Some(child) => unsafe { libc::kill(child.id() as i32, 0) == 0 },
            None => false,
        };
        if !alive {
            return HealthStatus::Unhealthy { reason: 1 };
        }
        // 2. The local SOCKS inbound must actually accept connections: a real
        //    liveness probe through the proxy stack, not just a pid check.
        let addr = self.config.socks_socket_addr();
        match std::net::TcpStream::connect_timeout(
            &addr,
            std::time::Duration::from_millis(750),
        ) {
            Ok(_) => HealthStatus::Healthy,
            Err(_) => HealthStatus::Degraded { reason: 2 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::DriverError;

    fn sample_config() -> XrayConfig {
        XrayConfig {
            server: "proxy.example.com".to_string(),
            port: 443,
            uuid: secrecy::SecretString::from("11111111-2222-3333-4444-555555555555"),
            flow: Some("xtls-rprx-vision".to_string()),
            transport: XrayTransport::Tcp,
            tls: None,
            name: Some("main".to_string()),
            socks_port: 10808,
            http_port: 10809,
        }
    }

    #[test]
    fn test_xray_driver_creation() {
        let driver = XrayDriver::new(DriverId::Xray, sample_config());
        assert_eq!(driver.id(), DriverId::Xray);
        assert!(driver.child.is_none());
        assert_eq!(driver.label(), "main");
    }

    #[test]
    fn validation_rejects_bad_input() {
        let mut cfg = sample_config();
        cfg.server = "  ".into();
        assert!(matches!(
            cfg.validate(),
            Err(DriverError::ConfigInvalid(_))
        ));

        let mut cfg = sample_config();
        cfg.socks_port = cfg.http_port;
        assert!(cfg.validate().is_err());

        let mut cfg = sample_config();
        cfg.transport = XrayTransport::WebSocket { path: "no-slash".into() };
        assert!(cfg.validate().is_err());

        let mut cfg = sample_config();
        cfg.tls = Some(XrayTls {
            server_name: "  ".into(),
            allow_insecure: false,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn valid_config_passes_validation() {
        let cfg = sample_config();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn generate_config_honors_transport_and_tls() {
        let mut cfg = sample_config();
        cfg.transport = XrayTransport::WebSocket {
            path: "/ws".to_string(),
        };
        cfg.tls = Some(XrayTls {
            server_name: "sni.example.com".to_string(),
            allow_insecure: true,
        });
        let driver = XrayDriver::new(DriverId::Xray, cfg);
        let json: serde_json::Value =
            serde_json::from_str(&driver.generate_config()).expect("valid JSON");
        let out = &json["outbounds"][0];
        assert_eq!(out["protocol"], "vless");
        assert_eq!(out["streamSettings"]["network"], "ws");
        assert_eq!(out["streamSettings"]["security"], "tls");
        assert_eq!(
            out["streamSettings"]["tlsSettings"]["serverName"],
            "sni.example.com"
        );
        assert_eq!(out["streamSettings"]["wsSettings"]["path"], "/ws");
        let user = &out["settings"]["vnext"][0]["users"][0];
        assert_eq!(user["id"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(user["flow"], "xtls-rprx-vision");
        // Secret must not leak through structured serialization: the generated
        // config file contains the uuid by design (xray needs it), but the
        // driver's own serializable view must not expose it.
        let serialized = serde_json::to_string(&driver.config).unwrap();
        assert!(!serialized.contains("11111111-2222-3333-4444-555555555555"));
    }

    #[test]
    fn generate_config_tcp_no_tls() {
        let cfg = sample_config();
        let driver = XrayDriver::new(DriverId::Xray, cfg);
        let json: serde_json::Value =
            serde_json::from_str(&driver.generate_config()).expect("valid JSON");
        let out = &json["outbounds"][0];
        assert_eq!(out["streamSettings"]["network"], "tcp");
        assert_eq!(out["streamSettings"]["security"], "none");
        assert_eq!(json["inbounds"][0]["port"], 10808);
        assert_eq!(json["inbounds"][1]["port"], 10809);
        assert_eq!(json["inbounds"][0]["listen"], "127.0.0.1");
    }

    #[test]
    fn serde_defaults_for_inbound_ports() {
        // Backward compatibility: configs serialized before the management
        // plane fields must still parse with default inbound ports.
        let toml = r#"
server = "a.example.com"
port = 443
uuid = "11111111-2222-3333-4444-555555555555"
transport = "Tcp"
"#;
        let cfg: XrayConfig = toml::from_str(toml).expect("parse with defaults");
        assert_eq!(cfg.socks_port, 10808);
        assert_eq!(cfg.http_port, 10809);
        assert!(cfg.name.is_none());
    }
}
