use balansir_common::event_bus::BoundedEventBus;
use balansir_common::ipc::{IpcMessage, IpcServerConnection, MsgType};
use balansir_common::metrics::SharedMetrics;
use balansir_common::{DesiredState, DriverId, Result};
use balansir_control::ReconcileReason;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

use balansir_daemon::driver::factory::ConfiguredFactory;
use balansir_daemon::driver::health::TierTracker;
use balansir_daemon::driver::lifecycle::{DriverIntent, DriverLifecycleManager};
use balansir_daemon::reconciliation::{ExecutorClient, Reconciler, ReconcilerConfig};

const SOCKET_PATH: &str = "/run/balansir/daemon.sock";
const SOCKET_PERMS: u32 = 0o600;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("balansir_daemon=debug")
        .init();

    info!("BalanSir Daemon starting");

    let socket_path = Path::new(SOCKET_PATH);
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    remove_stale_socket(socket_path)?;

    let listener = UnixListener::bind(socket_path)?;
    tokio::fs::set_permissions(socket_path, Permissions::from_mode(SOCKET_PERMS)).await?;
    info!("Listening on {} (mode {:#o})", SOCKET_PATH, SOCKET_PERMS);

    // Driver lifecycle state machine (ADR-011). Real driver configs are wired
    // via the typed ConfiguredFactory (M3.5); until a config source is loaded
    // the registry is empty and every Start fails honestly as a tracked Failed
    // slot.
    let lifecycle: Arc<tokio::sync::Mutex<DriverLifecycleManager>> =
        Arc::new(tokio::sync::Mutex::new(DriverLifecycleManager::new(
            Box::new(ConfiguredFactory::empty()),
        )));

    // M3.3 observability: shared metrics + event bus + tier tracker, fed by the
    // orchestration layer (NOT by the lifecycle manager itself, per ADR-012).
    let metrics = Arc::new(SharedMetrics::new());
    let events: Arc<BoundedEventBus> = Arc::new(BoundedEventBus::new(1024));
    let tracker = Arc::new(tokio::sync::Mutex::new(TierTracker::default()));

    // M3.4.1 production control plane: the daemon binary now drives the real
    // Coordinator -> BasicPlanner -> plan -> execution-adapter -> ActualState
    // path. Per ADR-013 the daemon is the commander: it sends operations to
    // the privileged executor server via ExecutorClient. If the executor is
    // unreachable the reconcile fails and rolls back — ActualState is never
    // faked. Driver lifecycle (above) remains a separate path.
    let reconciler = Arc::new(Reconciler::new(
        balansir_common::DesiredState::default(),
        Arc::new(ExecutorClient::default()),
        ReconcilerConfig::default(),
    ));
    // A2: seed ActualState from the executor's kernel inventory so any rule
    // left behind by an ack-gap/executor restart is reconciled (removed if not
    // desired). Non-authoritative — the daemon still decides what should be.
    if let Err(e) = reconciler.sync_actual_from_executor().await {
        warn!("Could not read executor inventory (will reconcile anyway): {e}");
    }
    match reconciler.reconcile().await {
        Ok(()) => info!("Initial reconcile: no changes required"),
        Err(e) => warn!(
            "Initial reconcile incomplete (executor unreachable or op failed): {}",
            e
        ),
    }

    // P4.1 (ADR-020) ownership loop: converge Desired → kernel on a cadence,
    // re-seeding ActualState from the executor inventory periodically so
    // external kernel edits and executor restarts are discovered, not just
    // startup orphans.
    let loop_reconciler = Arc::clone(&reconciler);
    tokio::spawn(async move {
        loop_reconciler.run_loop().await;
    });

    // P6 (ADR-023) DNS plane: a shared DNS registry (populated by the DNS
    // forwarder/observation feed) feeds the flow compiler, which expands
    // domain rules into per-IP rules. The compiler is registered on the
    // reconciler so set_desired/reload expand domains, and the dns_loop
    // re-compiles on DNS changes without a manual reload.
    let dns_registry = std::sync::Arc::new(balansir_daemon::reconciliation::DnsRegistry::new());
    let compiler = balansir_daemon::reconciliation::FlowCompiler::new((*dns_registry).clone());
    reconciler.with_flow_compiler(compiler).await;

    let dns_loop_reconciler = Arc::clone(&reconciler);
    tokio::spawn(async move {
        dns_loop_reconciler.dns_loop().await;
    });

    // P7.1 (ADR-024) B4 runtime loop: policy-controlled connectivity
    // adaptation. Loads the optional B4 config (BALANSIR_B4_CONFIG) and runs
    // the engine with a host-stack observer. The observer is the Noop source
    // until a real TCP_INFO/DNS observer is wired (P7.2); the engine is fully
    // testable regardless. Decisions are logged; execution of MTU/DNS-path
    // changes is the P7.2 mechanism step.
    if let Ok(b4_path) = std::env::var("BALANSIR_B4_CONFIG") {
        match balansir_daemon::b4_engine::config::B4Toml::from_file(&b4_path) {
            Ok(b4_cfg) => match b4_cfg.policy() {
                Ok(policy) => {
                    let engine_cfg = b4_cfg.engine_config();
                    let observer: std::sync::Arc<dyn balansir_daemon::b4_engine::B4Observer> =
                        std::sync::Arc::new(balansir_daemon::b4_engine::observe::NoopObserver);
                    let mut engine = balansir_daemon::b4_engine::B4Engine::with_config(
                        policy, observer, engine_cfg,
                    );
                    tokio::spawn(async move {
                        engine
                            .run_loop(10, |flow, decision| async move {
                                info!(flow, decision = ?decision, "B4 decision");
                            })
                            .await;
                    });
                    info!("B4 engine started from {b4_path}");
                }
                Err(e) => warn!("B4 config {b4_path} policy rejected: {e} (engine disabled)"),
            },
            Err(e) => warn!("B4 config {b4_path} rejected: {e} (engine disabled)"),
        }
    }

    // Setup signal handlers
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        // Authenticate peer via SO_PEERCRED
                        match IpcServerConnection::accept(stream).await {
                            Ok(conn) => {
                                info!("Executor connected (UID: {})", conn.peer_uid());
                                let lifecycle = Arc::clone(&lifecycle);
                                let metrics = Arc::clone(&metrics);
                                let events = Arc::clone(&events);
                                let tracker = Arc::clone(&tracker);
                                let reconciler = Arc::clone(&reconciler);
                                tokio::spawn(handle_connection(
                                    conn,
                                    lifecycle,
                                    metrics,
                                    events,
                                    tracker,
                                    reconciler,
                                ));
                            }
                            Err(e) => {
                                warn!("Authentication failed: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                    }
                }
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down gracefully...");
                break;
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down gracefully...");
                break;
            }
        }
    }

    // Cleanup
    info!("Cleaning up...");
    if socket_path.exists() {
        if let Err(e) = tokio::fs::remove_file(socket_path).await {
            warn!("Failed to remove socket: {}", e);
        }
    }

    info!("BalanSir Daemon stopped");
    Ok(())
}

async fn handle_connection(
    mut conn: IpcServerConnection,
    lifecycle: Arc<tokio::sync::Mutex<DriverLifecycleManager>>,
    metrics: Arc<SharedMetrics>,
    events: Arc<BoundedEventBus>,
    tracker: Arc<tokio::sync::Mutex<TierTracker>>,
    reconciler: Arc<Reconciler>,
) {
    loop {
        match conn.recv().await {
            Ok(msg) => {
                let response = handle_message(
                    &msg,
                    Arc::clone(&lifecycle),
                    &metrics,
                    &events,
                    &tracker,
                    &reconciler,
                )
                .await;
                if let Err(e) = conn.send(&response).await {
                    error!("Send error: {}", e);
                    break;
                }
            }
            Err(e) => {
                error!("Recv error: {}", e);
                break;
            }
        }
    }
}

/// Payload of a driver message: a postcard-encoded `DriverId`.
fn driver_id_from_payload(msg: &IpcMessage) -> Option<DriverId> {
    postcard::from_bytes(&msg.payload).ok()
}

/// Reconcile tier tracking after any lifecycle-affecting operation. Emits
/// `ComponentHealthChanged` on the bus and updates gauges; tier changes are
/// pushed only when the tier actually differs (ADR-012).
async fn refresh_tiers(
    lifecycle: &tokio::sync::Mutex<DriverLifecycleManager>,
    metrics: &SharedMetrics,
    events: &BoundedEventBus,
    tracker: &tokio::sync::Mutex<TierTracker>,
) {
    let mut tracker_guard = tracker.lock().await;
    let manager = lifecycle.lock().await;
    tracker_guard.reconcile(&manager, metrics, events);
}

async fn handle_message(
    msg: &IpcMessage,
    lifecycle: Arc<tokio::sync::Mutex<DriverLifecycleManager>>,
    metrics: &SharedMetrics,
    events: &BoundedEventBus,
    tracker: &tokio::sync::Mutex<TierTracker>,
    reconciler: &Reconciler,
) -> IpcMessage {
    match msg.msg_type {
        MsgType::HealthCheck => {
            info!("Health check requested");
            IpcMessage::response_ok(msg.correlation_id)
        }
        MsgType::GetMetrics => {
            let body = metrics.encode_metrics().into_bytes();
            IpcMessage::response_data(msg.correlation_id, body)
        }
        MsgType::StartDriver | MsgType::RestartDriver => {
            let Some(id) = driver_id_from_payload(msg) else {
                return IpcMessage::response_error(msg.correlation_id, "Invalid driver id");
            };
            let fingerprint = id.as_u32() as u64;
            let intent = DriverIntent {
                id,
                action: if msg.msg_type == MsgType::RestartDriver {
                    balansir_common::DriverAction::Restart
                } else {
                    balansir_common::DriverAction::Start
                },
                fingerprint,
            };
            let failed = {
                let mut g = lifecycle.lock().await;
                let emitted = g.reconcile(vec![intent]).await;
                emitted.iter().any(|e| {
                    matches!(
                        e.outcome,
                        balansir_daemon::driver::lifecycle::DriverOutcome::Failed { .. }
                    )
                })
            };
            refresh_tiers(&lifecycle, metrics, events, tracker).await;
            if failed {
                info!(?id, "driver failed to start");
                IpcMessage::response_error(msg.correlation_id, "Driver failed to start")
            } else {
                info!(?id, "driver started");
                IpcMessage::response_ok(msg.correlation_id)
            }
        }
        MsgType::StopDriver => {
            let Some(id) = driver_id_from_payload(msg) else {
                return IpcMessage::response_error(msg.correlation_id, "Invalid driver id");
            };
            {
                let mut g = lifecycle.lock().await;
                g.reconcile(vec![DriverIntent::stop(id)]).await;
            }
            refresh_tiers(&lifecycle, metrics, events, tracker).await;
            info!(?id, "driver stopped");
            IpcMessage::response_ok(msg.correlation_id)
        }
        // M3.8 CLI / control-plane queries.
        MsgType::GetPlan => {
            let plan = reconciler.build_plan().await;
            let body = postcard::to_allocvec(&plan).unwrap_or_default();
            IpcMessage::response_data(msg.correlation_id, body)
        }
        MsgType::GetExplain => {
            let explanation = reconciler.explain().await;
            IpcMessage::response_data(msg.correlation_id, explanation.into_bytes())
        }
        MsgType::GetDesired => {
            let desired = reconciler.get_desired().await;
            let body = postcard::to_allocvec(&desired).unwrap_or_default();
            IpcMessage::response_data(msg.correlation_id, body)
        }
        MsgType::GetActual => {
            let actual = reconciler.get_actual().await;
            let body = postcard::to_allocvec(&actual).unwrap_or_default();
            IpcMessage::response_data(msg.correlation_id, body)
        }
        MsgType::GetConfigFingerprint => {
            let fp = reconciler.config_fingerprint().await;
            match postcard::to_allocvec(&fp) {
                Ok(body) => IpcMessage::response_data(msg.correlation_id, body),
                Err(_) => IpcMessage::response_error(msg.correlation_id, "encode failed"),
            }
        }
        MsgType::Reload => {
            let Ok(candidate) = postcard::from_bytes::<DesiredState>(&msg.payload) else {
                return IpcMessage::response_error(msg.correlation_id, "invalid reload payload");
            };
            match reconciler
                .reload(candidate, ReconcileReason::ConfigReload)
                .await
            {
                Ok(()) => IpcMessage::response_ok(msg.correlation_id),
                Err(e) => IpcMessage::response_error(msg.correlation_id, &e.to_string()),
            }
        }
        _ => {
            info!("Unknown message type: {:?}", msg.msg_type);
            IpcMessage::response_error(msg.correlation_id, "Unknown message type")
        }
    }
}

/// Safely remove a stale socket file. Refuses symlinks and sockets owned by
/// another UID, so an attacker-controlled file cannot be clobbered or trick us
/// into unlinking an unrelated path.
fn remove_stale_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let md = match std::fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    if !md.file_type().is_socket() {
        return Err(balansir_common::error::Error::Misconfiguration(format!(
            "refusing to remove non-socket at {}",
            path.display()
        )));
    }

    if md.uid() != unsafe { libc::geteuid() } {
        return Err(balansir_common::error::Error::IpcViolation(format!(
            "stale socket at {} owned by different UID",
            path.display()
        )));
    }

    std::fs::remove_file(path)?;
    warn!("Removed stale socket at {}", path.display());
    Ok(())
}
