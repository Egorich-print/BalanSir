use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// --- Type aliases ---

pub type EventId = u64;
pub type CorrelationId = u64;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Capabilities: u32 {
        const TUNNEL           = 0b00000001;
        const PROXY            = 0b00000010;
        const DNS              = 0b00000100;
        const FIREWALL         = 0b00001000;
        const QOS              = 0b00010000;
        const PACKET_PROCESSOR = 0b00100000;
        const UPDATER          = 0b01000000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded { reason: u32 },
    Unhealthy { reason: u32 },
    Unknown,
}

/// Coarse health tier used by observability and control-plane events.
///
/// Deliberately coarser than `HealthStatus` so consumers (metrics, SSE,
/// OpenTelemetry later) do not need to interpret per-reason codes. Ordering:
/// `Healthy < Degraded < Failing < Disabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum HealthTier {
    Healthy = 0,
    Degraded = 1,
    Failing = 2,
    Disabled = 3,
}

impl HealthTier {
    /// Numeric value for wire/metrics encoding.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Restore a tier from its numeric value (`HealthTier::as_u8`).
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Healthy),
            1 => Some(Self::Degraded),
            2 => Some(Self::Failing),
            3 => Some(Self::Disabled),
            _ => None,
        }
    }

    /// Short stable label for metrics/events.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Failing => "failing",
            Self::Disabled => "disabled",
        }
    }

    /// Fold a `HealthStatus` into a tier for uniform reporting.
    pub const fn from_health_status(status: &HealthStatus) -> Self {
        match status {
            HealthStatus::Healthy => Self::Healthy,
            HealthStatus::Degraded { .. } => Self::Degraded,
            HealthStatus::Unhealthy { .. } => Self::Failing,
            HealthStatus::Unknown => Self::Disabled,
        }
    }
}

/// A point-in-time view of driver health for policy evaluation.
///
/// The policy engine consults this to fail over `Forward { driver }` actions
/// when the target tunnel is `Unhealthy`. Implementations are expected to be
/// cheap and recently refreshed (the daemon refreshes it on a health-check
/// cycle; tests and simulators can build fixed snapshots).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthView {
    inner: std::collections::HashMap<DriverId, HealthStatus>,
}

impl HealthView {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a driver's current health status.
    pub fn set(&mut self, driver: DriverId, health: HealthStatus) {
        self.inner.insert(driver, health);
    }

    /// Bulk-update from an iterator of `(DriverId, HealthStatus)` pairs.
    pub fn extend(&mut self, iter: impl IntoIterator<Item = (DriverId, HealthStatus)>) {
        self.inner.extend(iter);
    }

    /// Health of the given driver, or `Unknown` when not tracked.
    pub fn status(&self, driver: DriverId) -> HealthStatus {
        self.inner
            .get(&driver)
            .copied()
            .unwrap_or(HealthStatus::Unknown)
    }

    /// Whether a driver is healthy enough to route through it.
    ///
    /// Only `Healthy` and `Unknown` are considered routable: `Degraded` and
    /// `Unhealthy` are not. This keeps the policy bail-out conservative.
    pub fn is_routable(&self, driver: DriverId) -> bool {
        matches!(
            self.status(driver),
            HealthStatus::Healthy | HealthStatus::Unknown
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriverAction {
    Start,
    Stop,
    Restart,
    Status,
}

// --- DriverId (enum for exhaustive matching) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DriverId {
    WireGuard,
    AmneziaWG,
    Xray,
    Hysteria,
    B4,
    DnsForwarder,
    /// Custom driver with numeric ID
    Custom(u32),
}

impl DriverId {
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::WireGuard => 1,
            Self::AmneziaWG => 2,
            Self::Xray => 3,
            Self::Hysteria => 4,
            Self::B4 => 5,
            Self::DnsForwarder => 6,
            Self::Custom(id) => *id,
        }
    }

    pub fn from_u32(id: u32) -> Self {
        match id {
            1 => Self::WireGuard,
            2 => Self::AmneziaWG,
            3 => Self::Xray,
            4 => Self::Hysteria,
            5 => Self::B4,
            6 => Self::DnsForwarder,
            n => Self::Custom(n),
        }
    }

    /// Resolve a driver name (as written in TOML/config) to a `DriverId`.
    ///
    /// Known drivers are matched case-insensitively by their canonical name
    /// (e.g. `wireguard`, `amneziawg`, `xray`, `hysteria`, `b4`,
    /// `dnsforwarder`). Unknown driver names resolve to `Custom`.
    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "wireguard" | "wg" => Self::WireGuard,
            "amneziawg" | "awg" => Self::AmneziaWG,
            "xray" | "xray-core" => Self::Xray,
            "hysteria" | "hysteria2" => Self::Hysteria,
            "b4" => Self::B4,
            "dnsforwarder" | "dns" => Self::DnsForwarder,
            _ => Self::Custom(hash_name(name)),
        }
    }

    /// Human-friendly driver identifier as used for routing/config.
    pub fn canonical_name(&self) -> &'static str {
        match self {
            Self::WireGuard => "wireguard",
            Self::AmneziaWG => "amneziawg",
            Self::Xray => "xray",
            Self::Hysteria => "hysteria",
            Self::B4 => "b4",
            Self::DnsForwarder => "dnsforwarder",
            Self::Custom(_) => "custom",
        }
    }
}

/// Stable FNV-1a hash used for custom driver names.
fn hash_name(name: &str) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in name.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

impl std::fmt::Display for DriverId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WireGuard => write!(f, "WireGuard"),
            Self::AmneziaWG => write!(f, "AmneziaWG"),
            Self::Xray => write!(f, "Xray"),
            Self::Hysteria => write!(f, "Hysteria"),
            Self::B4 => write!(f, "B4"),
            Self::DnsForwarder => write!(f, "DnsForwarder"),
            Self::Custom(id) => write!(f, "Custom({})", id),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverInfo {
    pub id: DriverId,
    pub name_hash: u32,
    pub capabilities: Capabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn other(&self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

// --- Decision Trace ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTrace {
    pub policy_id: u32,
    pub steps: smallvec::SmallVec<[MatcherStep; 4]>,
    pub action: Action,
    pub execution_time_us: u64,
    pub correlation_id: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MatcherStep {
    pub rule_id: u32,
    pub matched: bool,
    pub reason: u16,
}

// --- Actions ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Route traffic to specific routing table
    Route { table: u32 },

    /// Set firewall mark (fwmark)
    Mark { fwmark: u32 },

    /// Forward to tunnel driver
    Forward { driver: DriverId },

    /// Block traffic silently (drop)
    Block,

    /// Reject traffic with ICMP unreachable
    Reject,

    /// Allow traffic (no modification)
    Allow,

    /// Shape traffic (QoS)
    Shape { class: u32 },

    /// Log packet (for debugging)
    Log,
}

impl Action {
    pub fn action_type(&self) -> ActionType {
        match self {
            Self::Route { .. } => ActionType::Route,
            Self::Mark { .. } => ActionType::Mark,
            Self::Forward { .. } => ActionType::Forward,
            Self::Block => ActionType::Block,
            Self::Reject => ActionType::Reject,
            Self::Allow => ActionType::Allow,
            Self::Shape { .. } => ActionType::Shape,
            Self::Log => ActionType::Log,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    Route,
    Mark,
    Forward,
    Block,
    Reject,
    Allow,
    Shape,
    Log,
}

// --- Action Request (daemon -> executor) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub action: Action,
    /// Source IP (IPv4 or IPv6). `IpAddr::V4(0.0.0.0)` / unspecified means "no
    /// source matcher" (A4: IPv6 representable).
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub interface: u32,
    pub trace: DecisionTrace,
}

// --- Action Result (executor -> daemon) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionResult {
    /// Action was successfully applied
    Applied {
        execution_time_us: u64,
        rule_id: Option<u32>,
    },

    /// Action was already in desired state (idempotent)
    AlreadyApplied,

    /// Action failed
    Failed {
        error: ActionError,
        message: Option<String>,
    },

    /// Action should be retried later
    Retry { after_ms: u32, reason: String },

    /// Action type is not supported by this executor
    Unsupported { action_type: ActionType },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionError {
    PermissionDenied,
    ResourceExhausted,
    InvalidArgument,
    KernelError(u32),
    DriverNotAvailable(DriverId),
    Timeout,
    Unknown,
}

// --- Executor capabilities ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorCapabilities {
    pub supported_actions: Vec<ActionType>,
    pub max_rules: u32,
    pub max_fwmarks: u32,
    pub max_route_tables: u32,
}

// --- Desired State ---

/// Rule id reserved for the terminal fail-closed rule installed when a
/// fail-closed config compiles with an empty rule set (P1, ADR-019).
pub const FAIL_CLOSED_RULE_ID: u32 = u32::MAX;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DesiredState {
    pub rules: Vec<DesiredRule>,
    pub drivers: Vec<DesiredDriver>,
}

/// Stable FNV-1a fingerprint of a desired-state config (P4.8, ADR-021).
///
/// Computed over the postcard encoding of the whole `DesiredState`, so any
/// change to rules or drivers changes the fingerprint. Used by the daemon to
/// report which config is actually loaded (operator verification) and to
/// detect redundant reloads.
pub fn config_fingerprint(state: &DesiredState) -> u64 {
    let bytes = postcard::to_allocvec(state).unwrap_or_default();
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in &bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Optional flow criteria a desired rule matches on (A3, ADR-018).
///
/// All fields are optional: `None` means "any" (no kernel matcher). When
/// present, the daemon carries them into `ActionRequest` and the executor
/// compiles them into per-flow nft matchers (`ip/ip6 saddr`, `daddr`,
/// `th sport/dport`, `meta l4proto`) instead of a chain-level verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowCriteria {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<u8>,
    /// Domain matcher (A3, DNS/conn metadata). Consumed by the daemon's flow
    /// compiler at reload time to resolve concrete `dst_ip`s; the executor
    /// never receives a rule that still carries a domain.
    #[serde(default)]
    pub dst_domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredRule {
    pub id: u32,
    pub action: Action,
    pub priority: u32,
    /// Optional flow matcher. `None` = chain-level verdict (all flows).
    #[serde(default)]
    pub flow: Option<FlowCriteria>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DesiredDriver {
    pub id: DriverId,
    pub action: DriverAction,
}

// --- Actual State ---

/// Actual state of the system (what is currently applied)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActualState {
    pub active_rules: Vec<ActualRule>,
}

/// A single active rule in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActualRule {
    pub id: u32,
    pub action: Action,
    pub rule_id: Option<u32>,
    /// Flow criteria the installed rule matched on (A3). Defaults to `None`
    /// for chain-level rules and for back-compat in tests.
    #[serde(default)]
    pub flow: Option<FlowCriteria>,
}

#[cfg(test)]
mod driver_id_tests {
    use super::DriverId;

    #[test]
    fn known_names_resolve_to_variants() {
        assert_eq!(DriverId::from_name("wireguard"), DriverId::WireGuard);
        assert_eq!(DriverId::from_name("WIREGUARD"), DriverId::WireGuard);
        assert_eq!(DriverId::from_name("wg"), DriverId::WireGuard);
        assert_eq!(DriverId::from_name("amneziawg"), DriverId::AmneziaWG);
        assert_eq!(DriverId::from_name("xray"), DriverId::Xray);
        assert_eq!(DriverId::from_name("hysteria2"), DriverId::Hysteria);
        assert_eq!(DriverId::from_name("b4"), DriverId::B4);
        assert_eq!(DriverId::from_name("dns"), DriverId::DnsForwarder);
    }

    #[test]
    fn unknown_names_become_custom() {
        let id = DriverId::from_name("my-vpn");
        assert!(matches!(id, DriverId::Custom(_)));
        assert_eq!(DriverId::from_name("my-vpn"), id, "hash must be stable");
    }

    #[test]
    fn u32_roundtrip() {
        for id in [DriverId::WireGuard, DriverId::B4, DriverId::Custom(99)] {
            assert_eq!(DriverId::from_u32(id.as_u32()), id);
        }
    }
}

/// P4.8 (ADR-021): config fingerprint is stable for identical state and
/// changes for any rule/driver difference.
#[cfg(test)]
mod config_fingerprint_tests {
    use super::*;

    fn state(rules: Vec<(u32, Action)>) -> DesiredState {
        DesiredState {
            rules: rules
                .into_iter()
                .map(|(id, action)| DesiredRule {
                    id,
                    action,
                    priority: 0,
                    flow: None,
                })
                .collect(),
            drivers: vec![],
        }
    }

    #[test]
    fn identical_state_has_identical_fingerprint() {
        let a = state(vec![(1, Action::Block)]);
        let b = state(vec![(1, Action::Block)]);
        assert_eq!(config_fingerprint(&a), config_fingerprint(&b));
    }

    #[test]
    fn different_state_has_different_fingerprint() {
        let a = state(vec![(1, Action::Block)]);
        let b = state(vec![(1, Action::Allow)]);
        let c = state(vec![(1, Action::Block), (2, Action::Allow)]);
        assert_ne!(config_fingerprint(&a), config_fingerprint(&b));
        assert_ne!(config_fingerprint(&a), config_fingerprint(&c));
    }
}
