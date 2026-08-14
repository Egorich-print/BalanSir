use balansir_common::error::Error;
use balansir_common::ipc::IpcServerConnection;
use balansir_common::Result;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracing::{error, info, warn};

use balansir_executor::nftables::NftablesBackend;
use balansir_executor::service::{serve_connection, ExecutorServices, NftablesExecutor};

/// The executor is the privileged server (ADR-013): it binds a socket owned
/// by root and serves the daemon's command connection.
const SOCKET_PATH: &str = "/run/balansir/executor.sock";
const SOCKET_PERMS: u32 = 0o600;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("balansir_executor=debug")
        .init();

    // Privileged executor must never run as an unprivileged user: netlink and
    // nftables require real root. Refuse to start otherwise.
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        error!(
            "Executor requires root (effective UID {}), refusing to start",
            uid
        );
        return Err(Error::Misconfiguration(format!(
            "executor must run as root, effective UID {}",
            uid
        )));
    }

    info!("BalanSir Executor starting (UID 0)");

    let socket_path = Path::new(SOCKET_PATH);
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    remove_stale_socket(socket_path)?;

    let listener = tokio::net::UnixListener::bind(socket_path)?;
    tokio::fs::set_permissions(socket_path, Permissions::from_mode(SOCKET_PERMS)).await?;
    info!("Listening on {} (mode {:#o})", SOCKET_PATH, SOCKET_PERMS);

    // Privileged mechanism. The nft binary may be absent in some environments;
    // construction is fallible so a missing mechanism is a hard, observable
    // failure rather than a silent no-op.
    let backend = NftablesBackend::new("balansir", "forward")
        .map_err(|e| Error::Misconfiguration(format!("nftables backend: {e}")))?;
    // Create the table + chain once, before serving any request. Without this
    // every AddRule would fail with "No such file or directory" (the table
    // does not exist yet) — the netns tests call setup() themselves, so the
    // production path must do it here.
    backend
        .init()
        .map_err(|e| Error::Misconfiguration(format!("nftables init: {e}")))?;
    let executor = Box::new(NftablesExecutor::new(backend));

    // Additional privileged mechanisms. Each is wired independently so a
    // missing optional mechanism degrades gracefully instead of killing the
    // whole executor:
    // - QoS: netlink tc (requires CAP_NET_ADMIN; falls back to record-only).
    // - Interface: netlink link ops (falls back to read-only sysfs).
    // - Tailscale: the upstream `tailscale` binary (absent => Status reports
    //   "not installed"; the executor still serves the rest).
    let qos: Box<dyn balansir_executor::qdisc::QosBackend> = build_qos_backend().await;
    let interface: Box<dyn balansir_executor::interface::InterfaceBackend> =
        build_interface_backend().await;

    let tailscale: Box<dyn balansir_executor::tailscale::TailscaleDriver> =
        match balansir_executor::tailscale::CliTailscaleDriver::new() {
            Ok(d) => Box::new(d),
            Err(e) => {
                warn!("Tailscale binary unavailable ({e}); status will report absent");
                Box::new(balansir_executor::tailscale::AbsentTailscaleDriver)
            }
        };

    let services = std::sync::Arc::new(ExecutorServices::new(executor, qos, interface, tailscale));

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // Authenticate the connecting peer (the daemon) before serving.
                match IpcServerConnection::accept(stream).await {
                    Ok(mut conn) => {
                        info!("Daemon connected (peer UID {})", conn.peer_uid());
                        let services = std::sync::Arc::clone(&services);
                        tokio::spawn(async move {
                            if let Err(e) = serve_connection(&mut conn, services.as_ref()).await {
                                warn!("Executor connection ended: {}", e);
                            }
                        });
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
}

/// Safely remove a stale socket file (mirror of the daemon's helper): refuse
/// symlinks and sockets owned by another UID.
fn remove_stale_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let md = match std::fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    if !md.file_type().is_socket() {
        return Err(Error::Misconfiguration(format!(
            "refusing to remove non-socket at {}",
            path.display()
        )));
    }

    if md.uid() != unsafe { libc::geteuid() } {
        return Err(Error::IpcViolation(format!(
            "stale socket at {} owned by different UID",
            path.display()
        )));
    }

    std::fs::remove_file(path)?;
    warn!("Removed stale socket at {}", path.display());
    Ok(())
}

#[cfg(target_os = "linux")]
async fn build_qos_backend() -> Box<dyn balansir_executor::qdisc::QosBackend> {
    match balansir_executor::qdisc::TcNetlinkBackend::new().await {
        Ok(b) => Box::new(b),
        Err(e) => {
            warn!("QoS netlink backend unavailable ({e}); record-only fallback");
            Box::new(balansir_executor::qdisc::RecordOnlyBackend::default())
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn build_qos_backend() -> Box<dyn balansir_executor::qdisc::QosBackend> {
    Box::new(balansir_executor::qdisc::RecordOnlyBackend::default())
}

#[cfg(target_os = "linux")]
async fn build_interface_backend() -> Box<dyn balansir_executor::interface::InterfaceBackend> {
    match balansir_executor::interface::NetlinkInterfaceBackend::new().await {
        Ok(b) => Box::new(b),
        Err(e) => {
            warn!("Interface netlink backend unavailable ({e}); sysfs fallback");
            Box::new(balansir_executor::interface::SysfsInterfaceBackend)
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn build_interface_backend() -> Box<dyn balansir_executor::interface::InterfaceBackend> {
    Box::new(balansir_executor::interface::SysfsInterfaceBackend)
}
