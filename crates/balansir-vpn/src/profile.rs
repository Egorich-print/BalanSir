//! VPN profile model: stable identity, protocol/transport metadata, and the
//! health/load vocabulary shared by the pool, selector and WebUI.
//!
//! Design rules (mission §8):
//! - **Stable identity** (`profile_id`) is a content hash of the *normalized*
//!   endpoint (protocol + address + port + transport + security), NOT the
//!   volatile runtime fields (latency, load, selection). A profile keeps the
//!   same id across health changes and pool reloads.
//! - **No credentials in metrics**: UUID/password live only in the raw
//!   profile and are never serialized into health/selection views.
//! - Every field that can be "unknown" is an `Option`/default; nothing is
//!   faked.

use serde::{Deserialize, Serialize};

/// Supported VPN protocols.
///
/// BalanSir only claims support for protocols the current runtime actually
/// speaks. The Xray integration speaks **VLESS** today (TCP/WS/gRPC/HTTPUpgrade
/// transports, optional reality/TLS). Other protocols are parsed and rejected
/// with a clear reason rather than silently mis-routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Vless,
}

impl Protocol {
    /// Canonical lowercase name (used as the "protocol" label everywhere).
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Vless => "vless",
        }
    }

    /// Recognized protocols the importer can parse. Unknown schemes are
    /// rejected during validation (never passed to the runtime).
    pub fn from_scheme(scheme: &str) -> Option<Protocol> {
        match scheme.trim().to_ascii_lowercase().as_str() {
            "vless" => Some(Protocol::Vless),
            _ => None,
        }
    }
}

/// Stream transport of a profile (the `type=` URI param / `network` field).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    /// WebSocket: path + optional Host header (the `host=` URI param — the
    /// fronting domain; required for correct WS+TLS fronting).
    WebSocket {
        path: String,
        host: Option<String>,
    },
    Grpc {
        service_name: String,
    },
    /// HTTPUpgrade: path + optional Host header (same `host=` param).
    HttpUpgrade {
        path: String,
        host: Option<String>,
    },
    /// XHTTP (a.k.a. splithttp / split-http): the modern CDN-friendly
    /// HTTP/2-based transport used by current Xray servers (mission §10).
    /// `mode` is `"auto"` | `"packet-up"` | `"stream-up"`; `extra` is optional
    /// opaque JSON (e.g. `{"maxConcurrency":8,"mode":"auto"}`).
    Xhttp {
        path: String,
        host: Option<String>,
        mode: Option<String>,
        extra: Option<String>,
    },
}

impl Transport {
    /// Stable, WebUI-friendly label.
    pub fn name(&self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::WebSocket { .. } => "ws",
            Transport::Grpc { .. } => "grpc",
            Transport::HttpUpgrade { .. } => "httpupgrade",
            Transport::Xhttp { .. } => "xhttp",
        }
    }
}

/// Security layer of a profile (`security=` URI param).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    None,
    Tls,
    Reality,
}

impl Security {
    pub fn name(&self) -> &'static str {
        match self {
            Security::None => "none",
            Security::Tls => "tls",
            Security::Reality => "reality",
        }
    }
}

/// A validated, normalized VPN endpoint profile.
///
/// `uuid`/`password` (the credentials) are kept here — the importer writes
/// them from the source config — but **never** leak into the health/selection
/// views (`ProfileHealth`, `ProfileRuntime`, snapshots). `Debug` does not
/// print them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnProfile {
    /// Stable content hash of the normalized endpoint.
    pub profile_id: String,
    pub protocol: Protocol,
    /// Endpoint host (IP or domain), validated.
    pub server: String,
    pub port: u16,
    pub transport: Transport,
    pub security: Security,
    /// SNI for TLS/reality (validated when present).
    pub sni: Option<String>,
    /// Reality `pbk` public key (validated format), kept for the runtime.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality_pbk: Option<String>,
    /// Reality short id (`sid`), if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality_sid: Option<String>,
    /// XTLS flow (e.g. `xtls-rprx-vision`), if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    /// VLESS UUID credential.
    #[serde(skip_serializing)]
    pub uuid: String,
    /// Client fingerprint (`fp=`), kept for runtime config fidelity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Human label from the source URI fragment (may be percent-encoded).
    pub label: String,
    /// Source identifier (which subscription file / URL produced this).
    pub source: String,
    /// Unix epoch millis the source was fetched.
    pub source_ts_ms: i64,
}

impl VpnProfile {
    /// The endpoint this profile reaches, as `server:port` (label-safe);
    /// bare IPv6 literals are bracketed (`[2001:db8::1]:443`) so the string
    /// stays unambiguous.
    pub fn endpoint(&self) -> String {
        if self.server.contains(':') && !self.server.starts_with('[') {
            format!("[{}]:{}", self.server, self.port)
        } else {
            format!("{}:{}", self.server, self.port)
        }
    }
}

/// Health/load runtime state of one profile. Never carries credentials.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProfileHealth {
    /// Stable profile identity (filled by the pool snapshot).
    #[serde(default)]
    pub profile_id: String,
    /// Human label from the source config (filled by the pool snapshot).
    #[serde(default)]
    pub label: String,
    pub state: ProfileState,
    /// EMA latency in ms (None until sampled).
    pub latency_ms: Option<f64>,
    /// EMA packet loss % (None until sampled).
    pub loss_pct: Option<f64>,
    /// Availability = 1 - failures / samples over the tracker lifetime.
    pub availability: Option<f64>,
    /// Consecutive successes (drives ramp-up).
    pub consecutive_successes: u32,
    /// Consecutive failures (drives failover / cooldown).
    pub consecutive_failures: u32,
    /// Total observed failures.
    pub failure_count: u64,
    /// Total observed samples.
    pub sample_count: u64,
    /// Ramp-up weight step for recovery (see `VpnPool::recovery_ramp`).
    pub weight: u32,
    /// Human-readable reasons behind the current state.
    pub reasons: Vec<String>,
}

/// Per-profile lifecycle state (mission §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileState {
    #[default]
    Unknown,
    Healthy,
    Degraded,
    /// In cooldown after failures; excluded from selection until it elapses.
    Cooldown,
    Failed,
    /// Passed a probe after cooldown; ramping weight back up.
    Recovering,
}

impl ProfileState {
    pub fn label(&self) -> &'static str {
        match self {
            ProfileState::Unknown => "Unknown",
            ProfileState::Healthy => "Healthy",
            ProfileState::Degraded => "Degraded",
            ProfileState::Cooldown => "Cooldown",
            ProfileState::Failed => "Failed",
            ProfileState::Recovering => "Recovering",
        }
    }
}
