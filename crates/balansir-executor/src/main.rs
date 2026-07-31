use balansir_common::ipc::{self, IpcMessage, MsgType};
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

    let mut stream = UnixStream::connect(SOCKET_PATH).await?;
    info!("Connected to daemon at {}", SOCKET_PATH);

    let msg = IpcMessage::new(MsgType::HealthCheck, 1, Vec::new());
    ipc::send(&mut stream, &msg).await?;
    info!("Sent health check");

    match ipc::recv(&mut stream).await {
        Ok(response) => {
            info!("Received response: {:?}", response.msg_type);
        }
        Err(e) => {
            error!("Failed to receive response: {}", e);
        }
    }

    Ok(())
}
