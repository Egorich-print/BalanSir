# BalanSir — Full Architecture Review Request

**Repository:** https://github.com/Egorich-print/BalanSir

**Project:** BalanSir is a Network Policy Engine for Linux routers and gateways, written in Rust (~5700 lines).

---

## Context

BalanSir orchestrates VPN tunnels and proxies through a declarative policy engine. It targets embedded Linux devices (Milk-V Duo S 512MB RAM, RISC-V).

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    balansir-daemon (unprivileged)       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │  Policy   │  │ Reconciler│  │  Health  │             │
│  │  Engine   │  │  Loop     │  │ Monitor  │             │
│  └──────────┘  └──────────┘  └──────────┘             │
│                       │                                 │
│                  Binary IPC (postcard)                   │
│                       │                                 │
├───────────────────────┼─────────────────────────────────┤
│                       ▼                                 │
│  ┌──────────────────────────────────────────────────┐  │
│  │              balansir-executor (privileged)       │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐       │  │
│  │  │ Network  │  │ Driver   │  │ Resource │       │  │
│  │  │ Backend  │  │ Manager  │  │ Allocator│       │  │
│  │  └──────────┘  └──────────┘  └──────────┘       │  │
│  └──────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│                    Linux Kernel (nftables/netlink)       │
└─────────────────────────────────────────────────────────┘
```

### Crates

- `balansir-common` — Types, IPC, State, Metrics, Validation
- `balansir-daemon` — Policy Engine, Drivers, Reconciler, Health
- `balansir-executor` — Network Backend, nftables, Resource Allocator
- `balansir-api` — REST API (axum) + SSE event stream
- `balansir-tests` — Integration tests

### Drivers (6)

| Driver | Status | Type |
|--------|--------|------|
| WireGuard | Skeleton | TUNNEL |
| AmneziaWG | Skeleton | TUNNEL |
| Xray (VLESS) | Process mgmt | PROXY |
| Hysteria 2 | Process mgrt | PROXY |
| B4 | Skeleton | PACKET_PROCESSOR |
| DNS Forwarder | Stub | DNS |

### Key Design Decisions

1. **Privilege Separation**: unprivileged daemon + privileged executor via binary IPC
2. **Reconciliation Loop**: Kubernetes-style desired state management
3. **Driver Pattern**: trait-based abstraction for network services
4. **State Store**: Atomic file writes (FileStateStore)
5. **Event Bus**: BoundedEventBus with ring buffer
6. **Metrics**: Prometheus-compatible counters/gauges

---

## File Tree (5671 lines Rust)

```
crates/
├── balansir-common/          # 1200 lines
│   ├── src/lib.rs
│   ├── src/types.rs          # Capabilities, DriverId, Action, DesiredState
│   ├── src/ipc.rs            # Binary IPC (postcard, Unix sockets)
│   ├── src/error.rs          # Error types (thiserror)
│   ├── src/event_bus.rs      # BoundedEventBus (ring buffer)
│   ├── src/state.rs          # StateStore trait
│   ├── src/state/file.rs     # FileStateStore (atomic writes)
│   ├── src/metrics.rs        # Prometheus metrics
│   ├── src/profile.rs        # Hardware profiles (TOML)
│   ├── src/resources.rs      # FwMark/Route table allocator
│   ├── src/validation.rs     # Config validation
│   └── src/version.rs        # IPC version constants
│
├── balansir-daemon/          # 2800 lines
│   ├── src/main.rs           # Entry point (tokio current_thread)
│   ├── src/lib.rs
│   ├── src/driver.rs         # ComponentDriver trait + DummyDriver
│   ├── src/health.rs         # CircuitBreaker
│   ├── src/policy/
│   │   ├── mod.rs            # PolicyEngine, PacketContext
│   │   ├── matcher.rs        # Matcher enum (Any, Domain, IP, Port, etc.)
│   │   └── rules.rs          # TOML rule loading
│   ├── src/reconciliation/
│   │   ├── mod.rs            # Reconciler, DriftItem
│   │   └── bootstrap.rs      # Crash recovery
│   ├── src/wireguard.rs      # WireGuard driver
│   ├── src/xray.rs           # Xray driver (VLESS)
│   ├── src/hysteria.rs       # Hysteria 2 driver
│   ├── src/amneziawg.rs      # AmneziaWG driver
│   ├── src/b4.rs             # B4 DPI bypass driver
│   └── src/dns.rs            # DNS forwarder (stub)
│
├── balansir-executor/        # 400 lines
│   ├── src/main.rs           # IPC client
│   ├── src/lib.rs
│   ├── src/executor.rs       # Executor trait + DummyExecutor
│   └── src/nftables.rs       # NftablesBackend
│
├── balansir-api/             # 500 lines
│   ├── src/lib.rs            # Axum router
│   └── src/handlers.rs       # REST + SSE handlers
│
└── balansir-tests/           # 400 lines
    ├── src/ipc_integration.rs # IPC tests
    └── src/netns.rs          # Network namespace tests
```

---

## Key Source Files (Core)

### types.rs — Core types
```rust
pub type EventId = u64;
pub type CorrelationId = u64;

bitflags! {
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

pub struct DriverId(pub u32);
impl DriverId {
    pub const WIREGUARD: DriverId = DriverId(1);
    pub const XRAY: DriverId = DriverId(2);
    pub const HYSTERIA: DriverId = DriverId(3);
    pub const B4: DriverId = DriverId(4);
}

pub enum Action {
    Route { table: u32 },
    Mark { fwmark: u32 },
    Forward { driver: DriverId },
    Block,
    Reject,
    Allow,
    Shape { class: u32 },
    Log,
}

pub enum ActionResult {
    Applied { execution_time_us: u64, rule_id: Option<u32> },
    AlreadyApplied,
    Failed { error: ActionError, message: Option<String> },
    Retry { after_ms: u32, reason: String },
    Unsupported { action_type: ActionType },
}
```

### ipc.rs — Binary IPC protocol
```rust
pub struct IpcMessage {
    pub version: u8,
    pub msg_type: MsgType,
    pub correlation_id: CorrelationId,
    pub payload: Vec<u8>,
}

pub struct IpcConnection {
    stream: UnixStream,
    next_correlation_id: u64,
}

impl IpcConnection {
    pub async fn send(&mut self, msg: &IpcMessage) -> Result<()> {
        let bytes = postcard::to_allocvec(msg)?;
        let len = (bytes.len() as u32).to_le_bytes();
        self.stream.write_all(&len).await?;
        self.stream.write_all(&bytes).await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<IpcMessage> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        // ... deserialize with postcard
    }
}
```

### driver.rs — ComponentDriver trait
```rust
#[async_trait]
pub trait ComponentDriver: Send + Sync {
    fn id(&self) -> DriverId;
    fn name(&self) -> &str;
    fn capabilities(&self) -> Capabilities;
    async fn start(&mut self) -> Result<(), String>;
    async fn stop(&mut self) -> Result<(), String>;
    async fn restart(&mut self) -> Result<(), String>;
    async fn health_check(&self) -> HealthStatus;
}
```

### health.rs — CircuitBreaker
```rust
pub struct CircuitBreaker {
    inner: Mutex<CircuitBreakerInner>,
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    pub fn state(&self) -> CircuitState { ... }
    pub fn record_success(&self) { ... }
    pub fn record_failure(&self) { ... }
    pub fn allow_request(&self) -> bool { ... }
    pub fn reset(&self) { ... }
}
```

### reconciliation/mod.rs — Reconciler
```rust
pub struct Reconciler {
    desired_state: Arc<tokio::sync::Mutex<DesiredState>>,
    actual_state: Arc<tokio::sync::Mutex<ActualState>>,
    executor: Arc<dyn ExecutorAdapter>,
    config: ReconcilerConfig,
}

impl Reconciler {
    pub async fn reconcile(&self) -> Result<(), String> { ... }
    pub async fn run_loop(&self) { ... } // runs forever
    async fn detect_drift(&self) -> Vec<DriftItem> { ... }
    async fn apply_desired_state(&self) -> Result<(), String> { ... }
}
```

### policy/matcher.rs — Rule matching
```rust
pub enum Matcher {
    Any,
    None,
    DomainSuffix { suffix: u32 },
    DomainExact { hash: u32 },
    IpRange { base: [u8; 4], mask: u8 },
    Port { port: u16 },
    PortRange { start: u16, end: u16 },
    Protocol { proto: u8 },
    Interface { id: u32 },
    All(Vec<Matcher>),
    AnyOf(Vec<Matcher>),
    Not(Box<Matcher>),
}

impl Matcher {
    pub fn matches(&self, ctx: &PacketContext) -> bool { ... }
}
```

### WireGuard driver example (shells out to `ip` command)
```rust
pub struct WireGuardDriver {
    id: DriverId,
    config: WireGuardConfig,
    running: bool,
    health: HealthStatus,
}

impl WireGuardDriver {
    fn create_interface(&self) -> Result<(), String> {
        let output = std::process::Command::new("ip")
            .args(["link", "add", &self.config.interface, "type", "wireguard"])
            .output()
            .map_err(|e| format!("Failed: {}", e))?;
        // ...
    }
}
```

---

## Review Questions

1. **Code Quality**: Idiomatic Rust? Clippy compliance? Any code smells?

2. **Error Handling**: Is `unwrap_or_else(|e| e.into_inner())` for Mutex poisoning acceptable? Any remaining unsafe patterns?

3. **Architecture**: Is the crate boundary separation correct? Dependency direction?

4. **Security**: Is privilege separation model sound? IPC authentication?

5. **Testing**: Is 66 tests sufficient? Missing test categories?

6. **Performance**: O(n) policy matching acceptable? IPC overhead?

7. **Production Readiness**: What's missing for v1.0?

Please provide:
- Executive summary
- Scorecard (Architecture / Rust idioms / Security / Testing / Documentation)
- Concrete findings with file:line references
- Priority (Critical / High / Medium / Low)
