use crate::error::Result;
use std::path::PathBuf;

pub mod file;

pub use file::FileStateStore;

pub struct StateStoreConfig {
    pub base_path: PathBuf,
}

impl Default for StateStoreConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("/var/lib/balansir/state"),
        }
    }
}

#[async_trait::async_trait]
pub trait StateStore: Send + Sync {
    async fn save(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn delete(&self, key: &str) -> Result<()>;
}
