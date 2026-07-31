use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub mod file;

pub use file::FileStateStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateBackend {
    File,
}

pub struct StateStoreConfig {
    pub base_path: PathBuf,
    pub backend: StateBackend,
    pub journal_capacity: usize,
}

impl Default for StateStoreConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("/var/lib/balansir/state"),
            backend: StateBackend::File,
            journal_capacity: 256,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEntry {
    pub timestamp: i64,
    pub component: u32,
    pub event_type: u8,
    pub data: Vec<u8>,
}

#[async_trait::async_trait]
pub trait StateStore: Send + Sync {
    async fn save(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn append_event(&self, event: &EventEntry) -> Result<()>;
    async fn query_events(&self, from: i64, to: i64) -> Result<Vec<EventEntry>>;
}

pub enum StateStoreImpl {
    File(FileStateStore),
}

impl StateStoreImpl {
    pub async fn new(config: &StateStoreConfig) -> Result<Self> {
        match config.backend {
            StateBackend::File => {
                let store = FileStateStore::new(config).await?;
                Ok(Self::File(store))
            }
        }
    }
}

#[async_trait::async_trait]
impl StateStore for StateStoreImpl {
    async fn save(&self, key: &str, data: &[u8]) -> Result<()> {
        match self {
            Self::File(s) => s.save(key, data).await,
        }
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self {
            Self::File(s) => s.load(key).await,
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        match self {
            Self::File(s) => s.delete(key).await,
        }
    }

    async fn append_event(&self, event: &EventEntry) -> Result<()> {
        match self {
            Self::File(s) => s.append_event(event).await,
        }
    }

    async fn query_events(&self, from: i64, to: i64) -> Result<Vec<EventEntry>> {
        match self {
            Self::File(s) => s.query_events(from, to).await,
        }
    }
}
