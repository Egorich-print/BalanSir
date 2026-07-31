use std::time::Duration;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Temporary failure: {0}")]
    Temporary(String),

    #[error("Retryable failure: {0}")]
    Retryable(String),

    #[error("Fatal error: {0}")]
    Fatal(String),

    #[error("Invalid configuration: {0}")]
    Misconfiguration(String),

    #[error("Unsupported on this hardware: {0}")]
    Unsupported(String),

    #[error("Circuit breaker is open")]
    CircuitOpen,

    #[error("IPC violation: {0}")]
    IpcViolation(String),

    #[error("Invalid IPC magic: expected 0x{expected:X}, got 0x{got:X}")]
    InvalidMagic { expected: u32, got: u32 },

    #[error("IPC version mismatch: remote={remote}, local={local}")]
    VersionMismatch { remote: u8, local: u8 },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },
}

impl Error {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Temporary(_) | Self::Retryable(_))
    }

    pub fn retry_delay(&self) -> Option<Duration> {
        match self {
            Self::Temporary(_) => Some(Duration::from_millis(100)),
            Self::Retryable(_) => Some(Duration::from_secs(5)),
            _ => None,
        }
    }
}

impl From<postcard::Error> for Error {
    fn from(e: postcard::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}
