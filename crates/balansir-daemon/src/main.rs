use balansir_common::event_bus::BoundedEventBus;
use balansir_common::ipc::{IpcMessage, IpcServerConnection, MsgType};
use balansir_common::metrics::SharedMetrics;
use balansir_common::{DriverId, Result};
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
    match reconciler.reconcile().await {
        Ok(()) => info!("Initial reconcile: no changes required"),
        Err(e) => warn!(
            "Initial reconcile incomplete (executor unreachable or op failed): {}",
            e
        ),
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
                                tokio::spawn(handle_connection(
                                    conn, lifecycle, metrics, events, tracker,
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
) {
    loop {
        match conn.recv().await {
            Ok(msg) => {
                let response =
                    handle_message(&msg, Arc::clone(&lifecycle), &metrics, &events, &tracker).await;
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
