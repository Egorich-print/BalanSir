use balansir_common::error::Error;
use balansir_common::ipc::{IpcConnection, MsgType};
use balansir_common::Result;
use tokio::net::UnixStream;
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

    let stream = UnixStream::connect(SOCKET_PATH).await?;
    let mut conn = IpcConnection::new(stream);
    info!("Connected to daemon at {}", SOCKET_PATH);

    let response = conn.request(MsgType::HealthCheck, Vec::new()).await?;
    info!("Health check response: {:?}", response.msg_type);

    Ok(())
}
