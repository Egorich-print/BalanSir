use balansir_common::ipc::{IpcConnection, IpcMessage, MsgType};
use balansir_common::Result;
use std::path::Path;
use tokio::net::UnixListener;
use tracing::{error, info};

const SOCKET_PATH: &str = "/tmp/balansir-test/daemon.sock";

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

    if socket_path.exists() {
        tokio::fs::remove_file(socket_path).await?;
    }

    let listener = UnixListener::bind(socket_path)?;
    info!("Listening on {}", SOCKET_PATH);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                info!("Executor connected");
                tokio::spawn(handle_connection(stream));
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

async fn handle_connection(stream: tokio::net::UnixStream) {
    let mut conn = IpcConnection::new(stream);

    loop {
        match conn.recv().await {
            Ok(msg) => {
                let response = handle_message(&msg);
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

fn handle_message(msg: &IpcMessage) -> IpcMessage {
    match msg.msg_type {
        MsgType::HealthCheck => {
            info!("Health check requested");
            IpcMessage::response_ok(msg.correlation_id)
        }
        MsgType::GetMetrics => {
            info!("Metrics requested");
            IpcMessage::response_ok(msg.correlation_id)
        }
        _ => {
            info!("Unknown message type: {:?}", msg.msg_type);
            IpcMessage::response_error(msg.correlation_id, "Unknown message type")
        }
    }
}
