use crate::error::{Error, Result};
use crate::version::{check_ipc_compatibility, IPC_VERSION};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub const MAX_PAYLOAD_SIZE: usize = 65536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MsgType {
    AddRule,
    RemoveRule,
    FlushRules,
    StartDriver,
    StopDriver,
    RestartDriver,
    HealthCheck,
    GetMetrics,
    ResponseOk,
    ResponseError,
    ResponseData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpcMessage {
    pub version: u8,
    pub msg_type: MsgType,
    pub sequence: u32,
    pub payload: Vec<u8>,
}

impl IpcMessage {
    pub fn new(msg_type: MsgType, sequence: u32, payload: Vec<u8>) -> Self {
        Self {
            version: IPC_VERSION,
            msg_type,
            sequence,
            payload,
        }
    }

    pub fn response_ok(sequence: u32) -> Self {
        Self::new(MsgType::ResponseOk, sequence, Vec::new())
    }

    pub fn response_error(sequence: u32, error: &str) -> Self {
        Self::new(MsgType::ResponseError, sequence, error.as_bytes().to_vec())
    }
}

pub async fn send(stream: &mut UnixStream, msg: &IpcMessage) -> Result<()> {
    let bytes = postcard::to_allocvec(msg)?;
    let len = (bytes.len() as u32).to_le_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn recv(stream: &mut UnixStream) -> Result<IpcMessage> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > MAX_PAYLOAD_SIZE {
        return Err(Error::PayloadTooLarge {
            size: len,
            max: MAX_PAYLOAD_SIZE,
        });
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;

    let msg: IpcMessage = postcard::from_bytes(&payload)?;

    if !check_ipc_compatibility(msg.version) {
        return Err(Error::VersionMismatch {
            remote: msg.version,
            local: IPC_VERSION,
        });
    }

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let msg = IpcMessage::new(MsgType::HealthCheck, 42, vec![1, 2, 3]);
        let bytes = postcard::to_allocvec(&msg).unwrap();
        let decoded: IpcMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.version, IPC_VERSION);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.payload, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_ipc_stream() {
        let (mut a, mut b) = UnixStream::pair().unwrap();

        let msg = IpcMessage::response_ok(1);
        send(&mut a, &msg).await.unwrap();

        let received = recv(&mut b).await.unwrap();
        assert_eq!(received.sequence, 1);
        assert_eq!(received.msg_type, MsgType::ResponseOk);
    }
}
