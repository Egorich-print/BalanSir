//! Configuration migration framework.
//!
//! Handles versioned configuration schema migrations that run automatically
//! on boot after an OTA update. Migrations are deterministic, idempotent,
//! and atomic - the original config is never destroyed until the new
//! config is successfully written and validated.

use balansir_common::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

/// Migration trait - implement for each schema version upgrade.
pub trait ConfigMigration: Send + Sync {
    /// Source schema version (e.g., 1 for v1->v2).
    fn from_version(&self) -> u32;

    /// Target schema version.
    fn to_version(&self) -> u32;

    /// Human-readable description.
    fn description(&self) -> &'static str;

    /// Perform the migration.
    ///
    /// Receives the parsed old config as a generic value.
    /// Returns the migrated config as a generic value.
    fn migrate(&self, old: serde_json::Value) -> Result<serde_json::Value>;

    /// Validate the migrated config.
    fn validate(&self, config: &serde_json::Value) -> Result<()>;
}

/// Migration registry - manages all available migrations.
pub struct MigrationRegistry {
    migrations: HashMap<(u32, u32), Box<dyn ConfigMigration>>,
}

impl MigrationRegistry {
    pub fn new() -> Self {
        Self {
            migrations: HashMap::new(),
        }
    }

    /// Register a migration.
    pub fn register<M: ConfigMigration + 'static>(&mut self, migration: M) {
        let key = (migration.from_version(), migration.to_version());
        info!(
            "Registered migration v{} -> v{}: {}",
            migration.from_version(),
            migration.to_version(),
            migration.description()
        );
        self.migrations.insert(key, Box::new(migration));
    }

    /// Get migration path from version A to version B.
    pub fn find_path(&self, from: u32, to: u32) -> Option<Vec<u32>> {
        if from == to {
            return Some(vec![from]);
        }
        if from > to {
            return None; // Downgrades not supported
        }

        // Simple linear path finding (migrations must be sequential)
        let mut path = vec![from];
        let mut current = from;
        while current < to {
            let next = current + 1;
            if self.migrations.contains_key(&(current, next)) {
                path.push(next);
                current = next;
            } else {
                return None;
            }
        }
        Some(path)
    }

    /// Apply migrations from version `from` to `to`.
    pub fn apply(
        &self,
        from: u32,
        to: u32,
        mut config: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = self.find_path(from, to).ok_or_else(|| {
            Error::Misconfiguration(format!("no migration path from v{} to v{}", from, to))
        })?;

        for window in path.windows(2) {
            let from_v = window[0];
            let to_v = window[1];
            let key = (from_v, to_v);
            if let Some(migration) = self.migrations.get(&key) {
                info!(
                    "Applying migration v{} -> v{}: {}",
                    from_v,
                    to_v,
                    migration.description()
                );
                config = migration.migrate(config)?;
                migration.validate(&config)?;
                info!("Migration v{} -> v{} completed", from_v, to_v);
            } else {
                return Err(Error::Misconfiguration(format!(
                    "missing migration v{} -> v{}",
                    from_v, to_v
                )));
            }
        }
        Ok(config)
    }
}

/// Configuration version wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedConfig {
    /// Schema version of this config.
    pub version: u32,

    /// The actual configuration data.
    pub config: serde_json::Value,
}

impl VersionedConfig {
    /// Create a new versioned config with current schema version.
    pub fn new(config: serde_json::Value) -> Self {
        Self {
            version: CURRENT_SCHEMA_VERSION,
            config,
        }
    }

    /// Load from file, applying migrations if needed.
    pub fn load(path: &Path, registry: &MigrationRegistry) -> Result<Self> {
        if !path.exists() {
            return Err(Error::Misconfiguration(format!(
                "config file not found: {}",
                path.display()
            )));
        }

        let content = fs::read_to_string(path).map_err(|e| Error::Io(e))?;

        let mut vc: VersionedConfig = serde_json::from_str(&content)
            .map_err(|e| Error::Misconfiguration(format!("parse config: {e}")))?;

        if vc.version < CURRENT_SCHEMA_VERSION {
            info!(
                "Migrating config from v{} to v{}",
                vc.version, CURRENT_SCHEMA_VERSION
            );
            vc.config = registry.apply(vc.version, CURRENT_SCHEMA_VERSION, vc.config)?;
            vc.version = CURRENT_SCHEMA_VERSION;

            // Write back migrated config
            vc.save(path)?;
        } else if vc.version > CURRENT_SCHEMA_VERSION {
            warn!(
                "Config version {} is newer than supported {}, skipping migration",
                vc.version, CURRENT_SCHEMA_VERSION
            );
        }

        Ok(vc)
    }

    /// Save config atomically.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::Io(e))?;
        }

        let content = serde_json::to_string_pretty(self)
            .map_err(|e| Error::Misconfiguration(format!("serialize config: {e}")))?;

        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, content).map_err(|e| Error::Io(e))?;
        fs::rename(&tmp, path).map_err(|e| Error::Io(e))?;

        Ok(())
    }
}

/// Current schema version - increment when adding migrations.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Global migration registry instance.
static MIGRATION_REGISTRY: std::sync::OnceLock<MigrationRegistry> = std::sync::OnceLock::new();

/// Get the global migration registry.
pub fn registry() -> &'static MigrationRegistry {
    MIGRATION_REGISTRY.get_or_init(|| {
        let mut reg = MigrationRegistry::new();
        // Register migrations here as they are added
        reg
    })
}

/// Migration runner - executes all pending migrations at startup.
pub struct MigrationRunner {
    registry: &'static MigrationRegistry,
    config_dir: PathBuf,
    backup_dir: PathBuf,
}

impl MigrationRunner {
    pub fn new(config_dir: impl AsRef<Path>, backup_dir: impl AsRef<Path>) -> Self {
        Self {
            registry: registry(),
            config_dir: config_dir.as_ref().to_path_buf(),
            backup_dir: backup_dir.as_ref().to_path_buf(),
        }
    }

    /// Run migrations for all config files in the config directory.
    pub fn run(&self) -> Result<MigrationReport> {
        let mut report = MigrationReport::default();

        if !self.config_dir.exists() {
            info!("Config directory does not exist, skipping migrations");
            return Ok(report);
        }

        fs::create_dir_all(&self.backup_dir).map_err(|e| Error::Io(e))?;

        for entry in fs::read_dir(&self.config_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json")
                || path.extension().and_then(|s| s.to_str()) == Some("toml")
            {
                match self.migrate_file(&path) {
                    Ok(migrated) => {
                        if migrated {
                            report.migrated.push(path.clone());
                        } else {
                            report.up_to_date.push(path.clone());
                        }
                    }
                    Err(e) => {
                        error!("Migration failed for {}: {}", path.display(), e);
                        report.failed.push((path.clone(), e.to_string()));
                    }
                }
            }
        }

        Ok(report)
    }

    fn migrate_file(&self, path: &Path) -> Result<bool> {
        let content = fs::read_to_string(path)?;
        let mut value: serde_json::Value =
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                toml::from_str(&content)
                    .map_err(|e| Error::Misconfiguration(format!("parse TOML: {e}")))?
            } else {
                serde_json::from_str(&content)
                    .map_err(|e| Error::Misconfiguration(format!("parse JSON: {e}")))?
            };

        // Extract version if present
        let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        if version == 0 {
            // No version field - assume legacy v0, add version and skip
            warn!("Config {} has no version, assuming v0", path.display());
            return Ok(false);
        }

        if version >= CURRENT_SCHEMA_VERSION {
            return Ok(false);
        }

        // Backup original
        let backup_path = self.backup_dir.join(format!(
            "{}.v{}.bak",
            path.file_name().unwrap().to_string_lossy(),
            version
        ));
        fs::copy(path, &backup_path).map_err(|e| Error::Io(e))?;

        // Apply migrations
        value = self
            .registry
            .apply(version, CURRENT_SCHEMA_VERSION, value)?;

        // Add version field
        if let Some(obj) = value.as_object_mut() {
            obj.insert(
                "version".into(),
                serde_json::Value::Number(CURRENT_SCHEMA_VERSION.into()),
            );
        }

        // Write new config
        let content = if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::to_string_pretty(&value)
                .map_err(|e| Error::Misconfiguration(format!("serialize TOML: {e}")))?
        } else {
            serde_json::to_string_pretty(&value)
                .map_err(|e| Error::Misconfiguration(format!("serialize JSON: {e}")))?
        };

        let tmp = path.with_extension("tmp");
        fs::write(&tmp, content)?;
        fs::rename(&tmp, path)?;

        info!(
            "Migrated {} from v{} to v{}",
            path.display(),
            version,
            CURRENT_SCHEMA_VERSION
        );
        Ok(true)
    }
}

/// Migration execution report.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MigrationReport {
    pub migrated: Vec<PathBuf>,
    pub up_to_date: Vec<PathBuf>,
    pub failed: Vec<(PathBuf, String)>,
}

impl MigrationReport {
    pub fn has_failures(&self) -> bool {
        !self.failed.is_empty()
    }
}

/// Run migrations at startup.
pub fn run_startup_migrations(config_dir: impl AsRef<Path>) -> Result<MigrationReport> {
    let backup_dir = config_dir.as_ref().join("migrations-backup");
    let runner = MigrationRunner::new(config_dir, backup_dir);
    runner.run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versioned_config_new() {
        let config = json!({"key": "value"});
        let vc = VersionedConfig::new(config.clone());
        assert_eq!(vc.version, CURRENT_SCHEMA_VERSION);
        assert_eq!(vc.config, config);
    }

    #[test]
    fn migration_registry_find_path() {
        let reg = MigrationRegistry::new();
        // No migrations registered, path only works for same version
        assert_eq!(reg.find_path(1, 1), Some(vec![1]));
        assert_eq!(reg.find_path(1, 2), None);
    }

    #[test]
    fn versioned_config_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");
        let config = json!({"test": "value"});
        let vc = VersionedConfig::new(config.clone());
        vc.save(&path).unwrap();

        let loaded = VersionedConfig::load(&path, registry()).unwrap();
        assert_eq!(loaded.version, CURRENT_SCHEMA_VERSION);
        assert_eq!(loaded.config, config);
    }
}
