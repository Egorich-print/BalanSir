use crate::error::{Error, Result};
use crate::state::{StateStore, StateStoreConfig};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::debug;

pub struct FileStateStore {
    base_path: PathBuf,
    allowed_keys: Vec<String>,
}

impl FileStateStore {
    pub async fn new(config: &StateStoreConfig) -> Result<Self> {
        let base_path = config.base_path.clone();

        fs::create_dir_all(&base_path).await?;
        fs::set_permissions(&base_path, std::fs::Permissions::from_mode(0o700)).await?;

        Ok(Self {
            base_path,
            allowed_keys: vec!["desired_state".to_string()],
        })
    }

    fn key_path(&self, key: &str) -> PathBuf {
        self.base_path.join(format!("{}.bin", key))
    }

    fn check_key(&self, key: &str) -> Result<()> {
        if !self.allowed_keys.contains(&key.to_string()) {
            return Err(Error::Misconfiguration(format!(
                "unknown state key: {}",
                key
            )));
        }
        Ok(())
    }

    fn sync_file(path: &Path) -> Result<()> {
        let f = std::fs::File::open(path)?;
        f.sync_all()?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl StateStore for FileStateStore {
    async fn save(&self, key: &str, data: &[u8]) -> Result<()> {
        self.check_key(key)?;
        let path = self.key_path(key);
        let tmp = path.with_extension("bin.tmp");

        fs::write(&tmp, data).await?;
        fs::rename(&tmp, &path).await?;
        Self::sync_file(&path)?;

        debug!("Saved state for key: {}", key);
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.check_key(key)?;
        let path = self.key_path(key);

        if path.exists() {
            let data = fs::read(&path).await?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.check_key(key)?;
        let path = self.key_path(key);

        if path.exists() {
            fs::remove_file(&path).await?;
            debug!("Deleted state for key: {}", key);
        }

        Ok(())
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
        };

        let store = FileStateStore::new(&config).await.unwrap();

        store.save("desired_state", b"hello").await.unwrap();
        let loaded = store.load("desired_state").await.unwrap();
        assert_eq!(loaded, Some(b"hello".to_vec()));

        store.delete("desired_state").await.unwrap();
        let loaded = store.load("desired_state").await.unwrap();
        assert_eq!(loaded, None);

        assert!(store.save("unknown", b"x").await.is_err());
    }

    #[tokio::test]
    async fn test_base_dir_mode_is_0700() {
        let dir = tempdir().unwrap();
        let config = StateStoreConfig {
            base_path: dir.path().to_path_buf(),
        };

        let _store = FileStateStore::new(&config).await.unwrap();
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
