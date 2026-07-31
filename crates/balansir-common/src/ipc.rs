use crate::error::{Error, Result};
use crate::types::CorrelationId;
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
    pub correlation_id: CorrelationId,
    pub payload: Vec<u8>,
}

impl IpcMessage {
    pub fn new(msg_type: MsgType, correlation_id: CorrelationId, payload: Vec<u8>) -> Self {
        Self {
            version: IPC_VERSION,
            msg_type,
            correlation_id,
            payload,
        }
    }

    pub fn response_ok(correlation_id: CorrelationId) -> Self {
        Self::new(MsgType::ResponseOk, correlation_id, Vec::new())
    }

    pub fn response_error(correlation_id: CorrelationId, error: &str) -> Self {
        Self::new(
            MsgType::ResponseError,
            correlation_id,
            error.as_bytes().to_vec(),
        )
    }

    pub fn response_data(correlation_id: CorrelationId, data: Vec<u8>) -> Self {
        Self::new(MsgType::ResponseData, correlation_id, data)
    }
}

pub struct IpcConnection {
    stream: UnixStream,
    next_correlation_id: u64,
}

impl IpcConnection {
    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            next_correlation_id: 1,
        }
    }

    pub fn next_correlation_id(&mut self) -> CorrelationId {
        let id = self.next_correlation_id;
        self.next_correlation_id += 1;
        id
    }

    pub async fn send(&mut self, msg: &IpcMessage) -> Result<()> {
        let bytes = postcard::to_allocvec(msg)?;
        let len = (bytes.len() as u32).to_le_bytes();
        self.stream.write_all(&len).await?;
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<IpcMessage> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;

        if len > MAX_PAYLOAD_SIZE {
            return Err(Error::PayloadTooLarge {
                size: len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).await?;

        let msg: IpcMessage = postcard::from_bytes(&payload)?;

        if !check_ipc_compatibility(msg.version) {
            return Err(Error::VersionMismatch {
                remote: msg.version,
                local: IPC_VERSION,
            });
        }

        Ok(msg)
    }

    pub async fn request(&mut self, msg_type: MsgType, payload: Vec<u8>) -> Result<IpcMessage> {
        let correlation_id = self.next_correlation_id();
        let msg = IpcMessage::new(msg_type, correlation_id, payload);
        self.send(&msg).await?;

        loop {
            let response = self.recv().await?;
            if response.correlation_id == correlation_id {
                return Ok(response);
            }
            // Ignore responses with different correlation IDs
        }
    }
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
        assert_eq!(decoded.correlation_id, 42);
        assert_eq!(decoded.payload, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_ipc_connection() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut conn_a = IpcConnection::new(a);
        let mut conn_b = IpcConnection::new(b);

        let msg = IpcMessage::response_ok(1);
        conn_a.send(&msg).await.unwrap();

        let received = conn_b.recv().await.unwrap();
        assert_eq!(received.correlation_id, 1);
        assert_eq!(received.msg_type, MsgType::ResponseOk);
    }
}
