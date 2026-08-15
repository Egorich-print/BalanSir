use crate::error::{Error, Result};
use crate::types::CorrelationId;
use crate::version::{check_ipc_compatibility, IPC_VERSION};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub const MAX_PAYLOAD_SIZE: usize = 65536;
// Default: root (operator CLI / privileged diagnostics) and UID 1500 (the
// unprivileged daemon account, ADR-030). Both daemon and executor accept
// these peers out of the box; an operator can override via BALANSIR_ALLOWED_UIDS.
pub const DEFAULT_ALLOWED_UIDS: &[u32] = &[0, 1500];

/// Allowed peer UIDs, from $BALANSIR_ALLOWED_UIDS (comma-separated) or default.
pub fn allowed_uids() -> Vec<u32> {
    match std::env::var("BALANSIR_ALLOWED_UIDS") {
        Ok(s) => s
            .split(',')
            .filter_map(|p| p.trim().parse::<u32>().ok())
            .collect(),
        Err(_) => DEFAULT_ALLOWED_UIDS.to_vec(),
    }
}

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
    // M3.8 CLI / control-plane queries (additions only; append-only).
    GetPlan,
    GetExplain,
    GetDesired,
    GetActual,
    Reload,
    // A2: executor reports its kernel inventory (non-authority) so the daemon
    // can reconcile orphans after an ack-gap/executor restart.
    GetActualRules,
    // P4.8: daemon reports the fingerprint of the last accepted desired-state
    // config so operators can verify what is actually loaded.
    GetConfigFingerprint,
    // P7.2 (ADR-026): B4 execution — per-path MTU adjustments. The executor
    // owns the applied path-MTU state and reports it (non-authority, like the
    // rule inventory) so the daemon can reconcile.
    SetPathMtu,
    RestorePathMtu,
    GetPathMtuState,
    // QoS / traffic shaping. Payloads are postcard-encoded `QosOp` (apply or
    // remove) and `Vec<AppliedQdisc>`/`QosCapabilities` responses.
    QosOp,
    GetQosState,
    GetQosCapabilities,
    // Interface driver: info + WAN MAC cloning (hardware MAC preserved and
    // restorable). Payloads are `InterfaceOp` / `InterfaceResult`.
    InterfaceOp,
    // Tailscale driver: status + controlled operations. Payloads are
    // `TailscaleOp` / `TailscaleResult`.
    TailscaleOp,
    // DPI-bypass queue-rule lifecycle. Payload is a postcard `DpiOp`: install
    // or remove the NFQUEUE interception rules (rendered with the `bypass`
    // keyword so a leftover rule can never blackhole traffic).
    DpiOp,
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

/// Fetch the peer's UID via the OS-native Unix socket credential mechanism.
///
/// Linux: `SO_PEERCRED` via `getsockopt` with a `ucred` struct (glibc and
/// musl both expose it through `libc`). Other Unixes (macOS/BSD, AIX, ...):
/// `getpeereid`. The returned value is the peer socket UID as reported by the
/// OS; the caller applies `allowed_uids()` unchanged.
#[cfg(target_os = "linux")]
fn peer_uid(fd: i32) -> Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return Err(Error::IpcViolation("Failed to get peer creds".into()));
    }

    Ok(cred.uid)
}

/// Non-Linux variant: `getpeereid` (POSIX/BSD-derived).
#[cfg(not(target_os = "linux"))]
fn peer_uid(fd: i32) -> Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;

    let ret = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };

    if ret != 0 {
        return Err(Error::IpcViolation("Failed to get peer creds".into()));
    }

    Ok(uid)
}

/// Validate peer credentials on Unix socket
/// Returns Ok(uid) if peer is authorized, Err otherwise
pub fn validate_peer_cred(stream: &UnixStream) -> Result<u32> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let uid = peer_uid(fd)?;

    let allowed = allowed_uids();
    if !allowed.contains(&uid) {
        return Err(Error::Unauthorized { uid, allowed });
    }

    Ok(uid)
}

/// Server-side connection wrapper with authentication
pub struct IpcServerConnection {
    inner: IpcConnection,
    peer_uid: u32,
}

impl IpcServerConnection {
    /// Accept a connection and validate credentials
    pub async fn accept(stream: UnixStream) -> Result<Self> {
        let peer_uid = validate_peer_cred(&stream)?;

        Ok(Self {
            inner: IpcConnection::new(stream),
            peer_uid,
        })
    }

    /// Get peer UID
    pub fn peer_uid(&self) -> u32 {
        self.peer_uid
    }

    /// Receive a message
    pub async fn recv(&mut self) -> Result<IpcMessage> {
        self.inner.recv().await
    }

    /// Send a message
    pub async fn send(&mut self, msg: &IpcMessage) -> Result<()> {
        self.inner.send(msg).await
    }
}

/// Client-side connection wrapper with mutual authentication.
pub struct IpcClientConnection {
    inner: IpcConnection,
    peer_uid: u32,
}

impl IpcClientConnection {
    /// Connect to a server and validate its credentials (SO_PEERCRED).
    pub async fn connect(path: &str) -> Result<Self> {
        let stream = tokio::net::UnixStream::connect(path).await?;
        Self::from_stream(stream).await
    }

    /// Wrap an already-connected stream and validate the server's credentials.
    pub async fn from_stream(stream: UnixStream) -> Result<Self> {
        let peer_uid = validate_peer_cred(&stream)?;
        Ok(Self {
            inner: IpcConnection::new(stream),
            peer_uid,
        })
    }

    /// Get connected server UID
    pub fn peer_uid(&self) -> u32 {
        self.peer_uid
    }

    /// Receive a message
    pub async fn recv(&mut self) -> Result<IpcMessage> {
        self.inner.recv().await
    }

    /// Send a message
    pub async fn send(&mut self, msg: &IpcMessage) -> Result<()> {
        self.inner.send(msg).await
    }

    /// Send a request and await the matching response.
    pub async fn request(&mut self, msg_type: MsgType, payload: Vec<u8>) -> Result<IpcMessage> {
        self.inner.request(msg_type, payload).await
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
