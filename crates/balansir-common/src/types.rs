use bitflags::bitflags;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverInfo {
    pub id: u32,
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

    /// Forward to tunnel driver (by driver ID hash)
    Forward { driver: u32 },

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
    Success {
        execution_time_us: u64,
        rule_id: Option<u32>,
    },
    Failed {
        error: ActionError,
    },
    Unsupported {
        action_type: ActionType,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionError {
    PermissionDenied,
    ResourceExhausted,
    InvalidArgument(String),
    KernelError(u32),
    DriverNotAvailable(u32),
    Timeout,
}

// --- Executor capabilities ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorCapabilities {
    pub supported_actions: Vec<ActionType>,
    pub max_rules: u32,
    pub max_fwmarks: u32,
    pub max_route_tables: u32,
}

// --- Event ID ---

pub type EventId = u64;

// --- Correlation ID ---

pub type CorrelationId = u64;

// --- Time abstraction ---

pub trait Clock: Send + Sync {
    fn now_millis(&self) -> i64;
    fn now_nanos(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64
    }

    fn now_nanos(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

pub struct MockClock {
    pub millis: std::sync::atomic::AtomicI64,
}

impl MockClock {
    pub fn new(initial: i64) -> Self {
        Self {
            millis: std::sync::atomic::AtomicI64::new(initial),
        }
    }

    pub fn advance(&self, ms: i64) {
        self.millis.fetch_add(ms, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for MockClock {
    fn now_millis(&self) -> i64 {
        self.millis.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn now_nanos(&self) -> u64 {
        (self.millis.load(std::sync::atomic::Ordering::Relaxed) * 1_000_000) as u64
    }
}
