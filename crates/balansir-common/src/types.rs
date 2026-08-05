use bitflags::bitflags;
use serde::{Deserialize, Serialize};

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
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DesiredState {
    pub rules: Vec<DesiredRule>,
    pub drivers: Vec<DesiredDriver>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredRule {
    pub id: u32,
    pub action: Action,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
