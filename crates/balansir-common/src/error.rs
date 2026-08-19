use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Driver-specific errors
#[derive(Debug, Error)]
pub enum DriverError {
    #[error("Config invalid: {0}")]
    ConfigInvalid(String),

    #[error("Start failed: {0}")]
    StartFailed(String),

    #[error("Stop failed: {0}")]
    StopFailed(String),

    #[error("Binary not found: {0}")]
    BinaryNotFound(String),

    #[error("Interface error: {0}")]
    InterfaceError(String),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Temporary failure: {0}")]
    Temporary(String),

    #[error("Fatal error: {0}")]
    Fatal(String),

    #[error("Invalid configuration: {0}")]
    Misconfiguration(String),

    #[error("Unsupported on this hardware: {0}")]
    Unsupported(String),

    #[error("IPC violation: {0}")]
    IpcViolation(String),

    #[error("Unauthorized: UID {uid} not in allowed list {allowed:?}")]
    Unauthorized { uid: u32, allowed: Vec<u32> },

    #[error("IPC version mismatch: remote={remote}, local={local}")]
    VersionMismatch { remote: u8, local: u8 },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("Driver error: {0}")]
    Driver(#[from] DriverError),
}

impl From<postcard::Error> for Error {
    fn from(e: postcard::Error) -> Self {
        Error::Serialization(e.to_string())
    }
}
