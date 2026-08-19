//! D3: Stress testing for balansir-common
//!
//! - IPC: 10k messages round-trip over Unix socket pair

use balansir_common::ipc::{IpcConnection, IpcMessage, MsgType};
use std::time::Instant;
use tokio::net::UnixStream;

/// IPC burst: 10_000 messages sent and received in order
#[tokio::test]
async fn ipc_burst_10000_messages() {
    let (a, b) = UnixStream::pair().unwrap();
    let mut sender = IpcConnection::new(a);
    let mut receiver = IpcConnection::new(b);

    const COUNT: u32 = 10_000;

    let start = Instant::now();
    let sender_task = tokio::spawn(async move {
        for i in 0..COUNT {
            let msg = IpcMessage::new(MsgType::HealthCheck, i as u64, vec![0xAB; 64]);
            sender.send(&msg).await.unwrap();
        }
    });

    let mut received = 0;
    for _ in 0..COUNT {
        let msg = receiver.recv().await.unwrap();
        assert_eq!(msg.msg_type, MsgType::HealthCheck);
        assert_eq!(msg.correlation_id, received);
        assert_eq!(msg.payload.len(), 64);
        assert!(msg.payload.iter().all(|&b| b == 0xAB));
        received += 1;
    }
    sender_task.await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(received, COUNT as u64);
    eprintln!(
        "ipc_burst_10000_messages: {} msgs in {:?} ({:.0} msgs/s)",
        COUNT,
        elapsed,
        COUNT as f64 / elapsed.as_secs_f64()
    );
}
