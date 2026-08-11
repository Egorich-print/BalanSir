use balansir_common::error::Error;
use balansir_common::ipc::IpcServerConnection;
use balansir_common::Result;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tracing::{error, info, warn};

use balansir_executor::nftables::NftablesBackend;
use balansir_executor::service::{serve_connection, NftablesExecutor};

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
    let executor = std::sync::Arc::new(NftablesExecutor::new(backend));

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                // Authenticate the connecting peer (the daemon) before serving.
                match IpcServerConnection::accept(stream).await {
                    Ok(mut conn) => {
                        info!("Daemon connected (peer UID {})", conn.peer_uid());
                        let executor = std::sync::Arc::clone(&executor);
                        tokio::spawn(async move {
                            if let Err(e) = serve_connection(&mut conn, executor.as_ref()).await {
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
