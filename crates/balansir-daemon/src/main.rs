use balansir_common::ipc::{IpcMessage, IpcServerConnection, MsgType};
use balansir_common::{DriverId, Result};
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

use balansir_daemon::driver::factory::NotYetWiredFactory;
use balansir_daemon::driver::lifecycle::{DriverIntent, DriverLifecycleManager};

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
    // in M3.4/M3.5; the factory keeps tracked-Failed slots until then.
    let lifecycle: Arc<tokio::sync::Mutex<DriverLifecycleManager>> = Arc::new(
        tokio::sync::Mutex::new(DriverLifecycleManager::new(Box::new(NotYetWiredFactory))),
    );

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
                                tokio::spawn(handle_connection(conn, lifecycle));
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
) {
    loop {
        match conn.recv().await {
            Ok(msg) => {
                let response = handle_message(&msg, Arc::clone(&lifecycle)).await;
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

async fn handle_message(
    msg: &IpcMessage,
    lifecycle: Arc<tokio::sync::Mutex<DriverLifecycleManager>>,
) -> IpcMessage {
    match msg.msg_type {
        MsgType::HealthCheck => {
            info!("Health check requested");
            IpcMessage::response_ok(msg.correlation_id)
        }
        MsgType::GetMetrics => {
            info!("Metrics requested");
            IpcMessage::response_ok(msg.correlation_id)
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
            let events = {
                let mut g = lifecycle.lock().await;
                g.reconcile(vec![intent]).await
            };
            if events.iter().any(|e| {
                matches!(
                    e.outcome,
                    balansir_daemon::driver::lifecycle::DriverOutcome::Failed { .. }
                )
            }) {
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
            let mut g = lifecycle.lock().await;
            g.reconcile(vec![DriverIntent::stop(id)]).await;
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
