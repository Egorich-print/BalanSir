use crate::error::Result;
use crate::state::{EventEntry, StateStore, StateStoreConfig};
use std::path::PathBuf;
use tokio::fs;
use tracing::debug;

pub struct FileStateStore {
    base_path: PathBuf,
    journal_path: PathBuf,
}

impl FileStateStore {
    pub async fn new(config: &StateStoreConfig) -> Result<Self> {
        let base_path = config.base_path.clone();
        let journal_path = base_path.join("events.journal");

        fs::create_dir_all(&base_path).await?;

        Ok(Self {
            base_path,
            journal_path,
        })
    }

    fn key_path(&self, key: &str) -> PathBuf {
        self.base_path.join(format!("{}.bin", key))
    }
}

#[async_trait::async_trait]
impl StateStore for FileStateStore {
    async fn save(&self, key: &str, data: &[u8]) -> Result<()> {
        let path = self.key_path(key);
        let tmp = path.with_extension("bin.tmp");

        fs::write(&tmp, data).await?;
        fs::rename(&tmp, &path).await?;

        debug!("Saved state for key: {}", key);
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.key_path(key);

        if path.exists() {
            let data = fs::read(&path).await?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.key_path(key);

        if path.exists() {
            fs::remove_file(&path).await?;
            debug!("Deleted state for key: {}", key);
        }

        Ok(())
    }

    async fn append_event(&self, event: &EventEntry) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.journal_path)
            .await?;

        let bytes = postcard::to_allocvec(event)?;
        let len = (bytes.len() as u32).to_le_bytes();

        file.write_all(&len).await?;
        file.write_all(&bytes).await?;
        file.flush().await?;

        debug!("Appended event to journal");
        Ok(())
    }

    async fn query_events(&self, from: i64, to: i64) -> Result<Vec<EventEntry>> {
        use tokio::io::AsyncReadExt;

        if !self.journal_path.exists() {
            return Ok(Vec::new());
        }

        let mut file = fs::File::open(&self.journal_path).await?;
        let mut events = Vec::new();

        loop {
            let mut len_buf = [0u8; 4];
            match file.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }

            let len = u32::from_le_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            file.read_exact(&mut payload).await?;

            let event: EventEntry = postcard::from_bytes(&payload)?;

            if event.timestamp >= from && event.timestamp <= to {
                events.push(event);
            }
        }

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_file_state_store() {
        let dir = tempdir().unwrap();
        let config = StateStoreConfig {
            base_path: dir.path().to_path_buf(),
            ..Default::default()
        };

        let store = FileStateStore::new(&config).await.unwrap();

        // Test save/load
        store.save("test", b"hello").await.unwrap();
        let loaded = store.load("test").await.unwrap();
        assert_eq!(loaded, Some(b"hello".to_vec()));

        // Test delete
        store.delete("test").await.unwrap();
        let loaded = store.load("test").await.unwrap();
        assert_eq!(loaded, None);
    }

    #[tokio::test]
    async fn test_event_journal() {
        let dir = tempdir().unwrap();
        let config = StateStoreConfig {
            base_path: dir.path().to_path_buf(),
            ..Default::default()
        };

        let store = FileStateStore::new(&config).await.unwrap();

        let event = EventEntry {
            timestamp: 1000,
            component: 1,
            event_type: 1,
            data: vec![1, 2, 3],
        };

        store.append_event(&event).await.unwrap();

        let events = store.query_events(0, 2000).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].timestamp, 1000);
    }
}
