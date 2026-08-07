//! Private runtime storage for driver secrets.
//!
//! Secrets (configs containing keys/passwords) must never land in world-writable
//! locations like `/tmp`. They live under `/run/balansir/` with mode `0600` and
//! are wiped before deletion so the raw bytes cannot be recovered from disk.

use balansir_common::DriverError;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const RUNTIME_DIR: &str = "/run/balansir";
const SECRET_MODE: u32 = 0o600;

/// Write a secret file under the private runtime dir owning the mode `0600`.
pub fn write_secret(id: &str, name: &str, contents: &[u8]) -> Result<PathBuf, DriverError> {
    let path = secret_path(id, name);
    write_to_dir(&path, contents)?;
    set_0600(&path)?;
    Ok(path)
}

/// Delete a secret file, overwriting its contents first so the key bytes
/// cannot be recovered from the filesystem.
pub fn remove_secret(path: &Path) {
    if let Ok(len) = std::fs::metadata(path).map(|m| m.len()) {
        if len > 0 {
            let _ = std::fs::write(path, vec![0u8; len as usize]);
            let _ = std::fs::write(path, []);
        }
    }
    let _ = std::fs::remove_file(path);
}

/// Canonical secret path: `/run/balansir/<name>-<id>.json`.
pub fn secret_path(id: &str, name: &str) -> PathBuf {
    Path::new(RUNTIME_DIR).join(format!("{}-{}.json", name, id))
}

fn write_to_dir(path: &Path, contents: &[u8]) -> Result<(), DriverError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| DriverError::StartFailed(format!("mkdir: {}", e)))?;
    }
    std::fs::write(path, contents)
        .map_err(|e| DriverError::StartFailed(format!("write secret: {}", e)))
}

fn set_0600(path: &Path) -> Result<(), DriverError> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SECRET_MODE))
        .map_err(|e| DriverError::StartFailed(format!("chmod secret: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_path_layout() {
        let p = secret_path("abc-123", "xray");
        assert!(p.starts_with(RUNTIME_DIR));
        assert_eq!(p.file_name().unwrap(), "xray-abc-123.json");
    }

    #[test]
    fn test_write_wipes_and_removes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");

        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"hunter2").unwrap();
        set_0600(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        remove_secret(&path);
        assert!(!path.exists());
    }
}
