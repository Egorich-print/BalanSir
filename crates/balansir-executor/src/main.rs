use balansir_common::error::Error;
use balansir_common::ipc::{IpcClientConnection, MsgType};
use balansir_common::Result;
use tracing::{error, info};

const SOCKET_PATH: &str = "/run/balansir/daemon.sock";

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

    let mut conn = IpcClientConnection::connect(SOCKET_PATH).await?;
    info!(
        "Connected to daemon at {} (peer UID {})",
        SOCKET_PATH,
        conn.peer_uid()
    );

    let response = conn.request(MsgType::HealthCheck, Vec::new()).await?;
    info!("Health check response: {:?}", response.msg_type);

    Ok(())
}
