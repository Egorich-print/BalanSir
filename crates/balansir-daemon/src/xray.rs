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
    #[serde(default)]
    pub security: XraySecurity,
    /// Optional profile/endpoint label (management plane).
    #[serde(default)]
    pub name: Option<String>,
    /// Local SOCKS5 inbound port (default 10808).
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
    /// Local HTTP inbound port (default 10809).
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    /// Split-tunnel domains (geo-spoofing): traffic to these domains is
    /// routed through this outbound; everything else goes direct. Empty =
    /// all proxied traffic goes through this outbound (legacy behavior).
    #[serde(default)]
    pub geo_domains: Vec<String>,
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
    WebSocket {
        path: String,
        /// Optional WS `Host` header (fronting domain from the source config).
        host: Option<String>,
    },
    Grpc {
        service_name: String,
    },
    HttpUpgrade {
        path: String,
        /// Optional `Host` header (fronting domain from the source config).
        host: Option<String>,
    },
    /// XHTTP (splithttp): the modern CDN-friendly HTTP/2 transport. `mode` is
    /// `"auto"`/`"packet-up"`/`"stream-up"`; `extra` is optional opaque JSON.
    Xhttp {
        path: String,
        /// Optional `Host` header (fronting domain from the source config).
        host: Option<String>,
        mode: Option<String>,
        extra: Option<String>,
    },
}

/// TLS layer: plain TLS (server name + optional certificate pinning) or
/// REALITY.
///
/// NOTE (Xray ≥26): the `allowInsecure` option was removed upstream
/// (migrated to `pinnedPeerCertSha256` / `verifyPeerCertByName` in 26.2.6 and
/// hard-disabled since 2026-06-01; configs still carrying it fail to build).
/// It is kept here only to *parse* legacy configs and reject them loudly —
/// never emitted into the generated runtime config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayTls {
    pub server_name: String,
    /// SHA-256 fingerprint(s) of the peer certificate (`pinnedPeerCertSha256`,
    /// comma-separated hex; any match passes verification).
    #[serde(default)]
    pub pinned_peer_cert_sha256: Option<String>,
    /// Override the server name used for certificate verification
    /// (`verifyPeerCertByName`, comma-separated domain list).
    #[serde(default)]
    pub verify_peer_cert_by_name: Option<String>,
    /// Legacy `allowInsecure` (removed in Xray ≥26). Parsed for backward
    /// compatibility only; `true` is rejected by `validate()`.
    #[serde(default)]
    pub allow_insecure: bool,
}

/// REALITY parameters (VLESS Reality outbound).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayReality {
    /// The REALITY server name (also acts as the SNI).
    pub server_name: String,
    /// Client fingerprint (`fp=`), e.g. `chrome` / `firefox`.
    pub fingerprint: String,
    /// The REALITY public key (`pbk`).
    pub public_key: String,
    /// Short id (`sid`), if the server uses one.
    #[serde(default)]
    pub short_id: String,
    /// Spider X path, when non-default.
    #[serde(default)]
    pub spider_x: String,
}

/// Security layer of an Xray outbound: plain (none), TLS, or REALITY.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XraySecurity {
    #[default]
    None,
    Tls(XrayTls),
    Reality(XrayReality),
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
            XrayTransport::WebSocket { path, .. }
            | XrayTransport::HttpUpgrade { path, .. }
            | XrayTransport::Xhttp { path, .. } => {
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
        match &self.security {
            XraySecurity::None => {}
            XraySecurity::Tls(tls) => {
                if tls.server_name.trim().is_empty() {
                    return Err(DriverError::ConfigInvalid(
                        "xray tls server_name must not be empty".into(),
                    ));
                }
                // allowInsecure was removed in Xray ≥26 (it now fails config
                // build). A legacy config still carrying `true` must not run
                // with silently-weaker TLS: reject it and name the migration.
                if tls.allow_insecure {
                    return Err(DriverError::ConfigInvalid(
                        "xray tls allow_insecure is not supported by Xray ≥26; \
                         migrate to pinned_peer_cert_sha256 (and/or verify_peer_cert_by_name)"
                            .into(),
                    ));
                }
            }
            XraySecurity::Reality(r) => {
                if r.server_name.trim().is_empty() {
                    return Err(DriverError::ConfigInvalid(
                        "xray reality server_name must not be empty".into(),
                    ));
                }
                if r.public_key.trim().is_empty() {
                    return Err(DriverError::ConfigInvalid(
                        "xray reality public_key must not be empty".into(),
                    ));
                }
                if r.fingerprint.trim().is_empty() {
                    return Err(DriverError::ConfigInvalid(
                        "xray reality fingerprint must not be empty".into(),
                    ));
                }
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
        XrayTransport::Xhttp { .. } => "xhttp",
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
        let (security, security_settings) = match &cfg.security {
            XraySecurity::None => ("none", None),
            XraySecurity::Tls(tls) => {
                let mut settings = serde_json::Map::new();
                settings.insert("serverName".into(), serde_json::json!(tls.server_name));
                // Xray ≥26 removed `allowInsecure`; pinning is the supported
                // path. Emit only the pin/verify fields when configured.
                if let Some(pcs) = &tls.pinned_peer_cert_sha256 {
                    if !pcs.trim().is_empty() {
                        settings.insert("pinnedPeerCertSha256".into(), serde_json::json!(pcs));
                    }
                }
                if let Some(vcn) = &tls.verify_peer_cert_by_name {
                    if !vcn.trim().is_empty() {
                        settings.insert("verifyPeerCertByName".into(), serde_json::json!(vcn));
                    }
                }
                ("tls", Some(settings))
            }
            XraySecurity::Reality(r) => {
                let mut settings = serde_json::Map::new();
                settings.insert("serverName".into(), serde_json::json!(r.server_name));
                settings.insert("fingerprint".into(), serde_json::json!(r.fingerprint));
                settings.insert("publicKey".into(), serde_json::json!(r.public_key));
                if !r.short_id.is_empty() {
                    settings.insert("shortId".into(), serde_json::json!(r.short_id));
                }
                if !r.spider_x.is_empty() {
                    settings.insert("spiderX".into(), serde_json::json!(r.spider_x));
                }
                ("reality", Some(settings))
            }
        };
        stream.insert("security".into(), serde_json::json!(security));
        if let Some(settings) = security_settings {
            let key = match security {
                "tls" => "tlsSettings",
                "reality" => "realitySettings",
                _ => "tlsSettings",
            };
            stream.insert(key.into(), serde_json::Value::Object(settings));
        }
        match &cfg.transport {
            XrayTransport::WebSocket { path, host } => {
                let mut ws = serde_json::json!({ "path": path });
                if let Some(host) = host {
                    if !host.is_empty() {
                        ws["headers"] = serde_json::json!({ "Host": host });
                    }
                }
                stream.insert("wsSettings".into(), ws);
            }
            XrayTransport::Grpc { service_name } => {
                stream.insert(
                    "grpcSettings".into(),
                    serde_json::json!({ "serviceName": service_name }),
                );
            }
            XrayTransport::HttpUpgrade { path, host } => {
                let mut hu = serde_json::json!({ "path": path });
                if let Some(host) = host {
                    if !host.is_empty() {
                        hu["host"] = serde_json::json!(host);
                    }
                }
                stream.insert("httpupgradeSettings".into(), hu);
            }
            XrayTransport::Xhttp {
                path,
                host,
                mode,
                extra,
            } => {
                // XHTTP settings: path (required), optional host/mode and
                // optional `extra` JSON (e.g. {"maxConcurrency":8}). Emitted
                // via serde so no string interpolation can break the JSON.
                let mut xh = serde_json::Map::new();
                xh.insert("path".into(), serde_json::json!(path));
                if let Some(host) = host {
                    if !host.is_empty() {
                        xh.insert("host".into(), serde_json::json!(host));
                    }
                }
                if let Some(mode) = mode {
                    if !mode.is_empty() {
                        xh.insert("mode".into(), serde_json::json!(mode));
                    }
                }
                if let Some(extra) = extra {
                    if !extra.is_empty() {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(extra) {
                            xh.insert("extra".into(), parsed);
                        }
                    }
                }
                stream.insert("xhttpSettings".into(), serde_json::Value::Object(xh));
            }
            XrayTransport::Tcp => {}
        }

        let mut user = serde_json::Map::new();
        user.insert("id".into(), serde_json::json!(cfg.uuid.expose_secret()));
        user.insert("encryption".into(), serde_json::json!("none"));
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
            "outbounds": serde_json::Value::Array({
                let vless = serde_json::json!({
                    "protocol": "vless",
                    "tag": "proxy",
                    "settings": {
                        "vnext": [{
                            "address": cfg.server,
                            "port": cfg.port,
                            "users": [ serde_json::Value::Object(user) ]
                        }]
                    },
                    "streamSettings": serde_json::Value::Object(stream)
                });
                // Split tunnel: when geo_domains are configured, the direct
                // (freedom) outbound comes FIRST so it is the default for all
                // traffic, and only the listed domains route through the VPN.
                // Without geo_domains, the proxy is the only outbound (legacy:
                // everything proxied goes through the VPN).
                if cfg.geo_domains.is_empty() {
                    vec![vless]
                } else {
                    vec![
                        serde_json::json!({ "protocol": "freedom", "tag": "direct" }),
                        vless,
                    ]
                }
            }),
            "dns": { "queryStrategy": "UseIP" },
            "routing": {
                "rules": [
                    {
                        "type": "field",
                        "domain": cfg.geo_domains,
                        "outboundTag": "proxy"
                    }
                ],
                "domainStrategy": "IPIfNonMatch"
            }
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
        match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(750)) {
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
            security: XraySecurity::None,
            name: Some("main".to_string()),
            socks_port: 10808,
            http_port: 10809,
            geo_domains: Vec::new(),
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
        assert!(matches!(cfg.validate(), Err(DriverError::ConfigInvalid(_))));

        let mut cfg = sample_config();
        cfg.socks_port = cfg.http_port;
        assert!(cfg.validate().is_err());

        let mut cfg = sample_config();
        cfg.transport = XrayTransport::WebSocket {
            path: "no-slash".into(),
            host: None,
        };
        assert!(cfg.validate().is_err());

        let mut cfg = sample_config();
        cfg.security = XraySecurity::Tls(XrayTls {
            server_name: "  ".into(),
            pinned_peer_cert_sha256: None,
            verify_peer_cert_by_name: None,
            allow_insecure: false,
        });
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn allow_insecure_true_is_rejected() {
        let mut cfg = sample_config();
        cfg.security = XraySecurity::Tls(XrayTls {
            server_name: "sni.example.com".into(),
            pinned_peer_cert_sha256: None,
            verify_peer_cert_by_name: None,
            allow_insecure: true,
        });
        assert!(cfg.validate().is_err(), "allowInsecure must be rejected");
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
            host: None,
        };
        cfg.security = XraySecurity::Tls(XrayTls {
            server_name: "sni.example.com".to_string(),
            pinned_peer_cert_sha256: Some(
                "e8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9".into(),
            ),
            verify_peer_cert_by_name: Some("alt.example.com".into()),
            allow_insecure: false,
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
        // Xray ≥26: allowInsecure must never be emitted; pinning fields are.
        assert!(
            out["streamSettings"]["tlsSettings"]
                .get("allowInsecure")
                .is_none(),
            "allowInsecure must not appear in the generated config"
        );
        assert_eq!(
            out["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"],
            "e8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9"
        );
        assert_eq!(
            out["streamSettings"]["tlsSettings"]["verifyPeerCertByName"],
            "alt.example.com"
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
    fn generate_config_xhttp_transport() {
        // Mission §10: xhttp (splithttp) must be fully supported in the
        // runtime config — lifecycle/health/integration use the same driver.
        let mut cfg = sample_config();
        cfg.transport = XrayTransport::Xhttp {
            path: "/vless".to_string(),
            host: Some("cdn.example.com".to_string()),
            mode: Some("auto".to_string()),
            extra: Some(r#"{"maxConcurrency":8}"#.to_string()),
        };
        cfg.security = XraySecurity::Tls(XrayTls {
            server_name: "cdn.example.com".to_string(),
            pinned_peer_cert_sha256: None,
            verify_peer_cert_by_name: None,
            allow_insecure: false,
        });
        assert!(cfg.validate().is_ok());
        let driver = XrayDriver::new(DriverId::Xray, cfg);
        let json: serde_json::Value =
            serde_json::from_str(&driver.generate_config()).expect("valid JSON");
        let out = &json["outbounds"][0];
        assert_eq!(out["streamSettings"]["network"], "xhttp");
        assert_eq!(out["streamSettings"]["security"], "tls");
        let xh = &out["streamSettings"]["xhttpSettings"];
        assert_eq!(xh["path"], "/vless");
        assert_eq!(xh["host"], "cdn.example.com");
        assert_eq!(xh["mode"], "auto");
        assert_eq!(xh["extra"]["maxConcurrency"], 8);
    }

    #[test]
    fn xhttp_path_must_start_with_slash() {
        let mut cfg = sample_config();
        cfg.transport = XrayTransport::Xhttp {
            path: "no-slash".to_string(),
            host: None,
            mode: None,
            extra: None,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn generate_config_split_tunnel_routes_geo_domains() {
        let mut cfg = sample_config();
        cfg.geo_domains = vec![
            "spotify.com".into(),
            "api.spotify.com".into(),
            "gemini.google.com".into(),
        ];
        let driver = XrayDriver::new(DriverId::Xray, cfg);
        let json: serde_json::Value =
            serde_json::from_str(&driver.generate_config()).expect("valid JSON");

        // Two outbounds: direct FIRST (default), then the tagged proxy.
        let outbounds = json["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 2, "split tunnel adds a direct outbound");
        assert_eq!(outbounds[0]["protocol"], "freedom");
        assert_eq!(outbounds[0]["tag"], "direct");
        assert_eq!(outbounds[1]["protocol"], "vless");
        assert_eq!(outbounds[1]["tag"], "proxy");

        // Routing: only geo domains go through the proxy.
        let rules = json["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["outboundTag"], "proxy");
        let domains = rules[0]["domain"].as_array().unwrap();
        assert!(domains.contains(&serde_json::json!("spotify.com")));
        assert!(domains.contains(&serde_json::json!("gemini.google.com")));
    }

    #[test]
    fn generate_config_without_geo_domains_has_single_outbound() {
        let driver = XrayDriver::new(DriverId::Xray, sample_config());
        let json: serde_json::Value =
            serde_json::from_str(&driver.generate_config()).expect("valid JSON");
        let outbounds = json["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 1, "no split tunnel without geo_domains");
        assert_eq!(outbounds[0]["protocol"], "vless");
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

    #[test]
    fn generate_config_honors_reality() {
        let mut cfg = sample_config();
        cfg.security = XraySecurity::Reality(XrayReality {
            server_name: "asia.example.com".into(),
            fingerprint: "firefox".into(),
            public_key: "REALITY_PUBKEY_1234567890".into(),
            short_id: "e53048e82bb20077".into(),
            spider_x: String::new(),
        });
        let driver = XrayDriver::new(DriverId::Xray, cfg);
        let json: serde_json::Value =
            serde_json::from_str(&driver.generate_config()).expect("valid JSON");
        let out = &json["outbounds"][0];
        assert_eq!(out["streamSettings"]["security"], "reality");
        let reality = &out["streamSettings"]["realitySettings"];
        assert_eq!(reality["serverName"], "asia.example.com");
        assert_eq!(reality["fingerprint"], "firefox");
        assert_eq!(reality["publicKey"], "REALITY_PUBKEY_1234567890");
        assert_eq!(reality["shortId"], "e53048e82bb20077");
        assert!(reality.get("spiderX").is_none());
    }
}
