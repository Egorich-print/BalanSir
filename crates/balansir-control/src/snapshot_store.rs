// crates/balansir-control/src/snapshot_store.rs

use crate::error::ControlResult;
use crate::traits::SnapshotStore;
use async_trait::async_trait;
use balansir_common::Snapshot;
use std::collections::HashMap;
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
