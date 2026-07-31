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

    info!("BalanSir Executor starting");

    let stream = UnixStream::connect(SOCKET_PATH).await?;
    let mut conn = IpcConnection::new(stream);
    info!("Connected to daemon at {}", SOCKET_PATH);

    let response = conn.request(MsgType::HealthCheck, Vec::new()).await?;
    info!("Health check response: {:?}", response.msg_type);

    Ok(())
}
