// crates/balansir-control/src/snapshot_store.rs

use crate::error::{ControlError, ControlResult};
use crate::traits::SnapshotStore;
use async_trait::async_trait;
use balansir_common::Snapshot;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock as AsyncRwLock;

/// In-memory snapshot store for tests and single-node deployments.
#[derive(Debug, Default)]
pub struct MemorySnapshotStore {
    snapshots: Arc<AsyncRwLock<HashMap<u64, Snapshot>>>,
}

impl MemorySnapshotStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SnapshotStore for MemorySnapshotStore {
    async fn load(&self, generation: u64) -> ControlResult<Option<Snapshot>> {
        let snapshots = self.snapshots.read().await;
        Ok(snapshots.get(&generation).cloned())
    }

    async fn save(&self, snapshot: &Snapshot) -> ControlResult<()> {
        let mut snapshots = self.snapshots.write().await;
        snapshots.insert(snapshot.metadata.generation, snapshot.clone());
        Ok(())
    }
}

/// File-based snapshot store.
///
/// Snapshots are serialized with postcard (binary) and stored in a directory
/// named by generation. Each snapshot is stored in a file named `{generation}.snap`.
#[derive(Debug, Clone)]
pub struct FileSnapshotStore {
    base_dir: PathBuf,
}

impl FileSnapshotStore {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }

    fn snapshot_path(&self, generation: u64) -> PathBuf {
        self.base_dir.join(format!("{}.snap", generation))
    }
}

#[async_trait]
impl SnapshotStore for FileSnapshotStore {
    async fn load(&self, generation: u64) -> ControlResult<Option<Snapshot>> {
        let path = self.snapshot_path(generation);
        if !tokio::fs::try_exists(&path)
            .await
            .map_err(|e| ControlError::SnapshotStore(format!("check exists {path:?}: {e}")))?
        {
            return Ok(None);
        }

        let bytes = tokio::fs::read(&path)
            .await
            .map_err(|e| ControlError::SnapshotStore(format!("read {path:?}: {e}")))?;

        let snapshot: Snapshot = postcard::from_bytes(&bytes)
            .map_err(|e| ControlError::SnapshotStore(format!("deserialize {path:?}: {e}")))?;

        Ok(Some(snapshot))
    }

    async fn save(&self, snapshot: &Snapshot) -> ControlResult<()> {
        let path = self.snapshot_path(snapshot.metadata.generation);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| ControlError::SnapshotStore(format!("mkdir {parent:?}: {e}")))?;
        }

        let bytes = postcard::to_vec::<_, 1024>(&snapshot)
            .map_err(|e| ControlError::SnapshotStore(format!("serialize: {e}")))?;

        tokio::fs::write(&path, &bytes)
            .await
            .map_err(|e| ControlError::SnapshotStore(format!("write {path:?}: {e}")))?;

        Ok(())
    }
}
