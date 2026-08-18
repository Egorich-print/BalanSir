//! A/B slot management and boot selection.
//!
//! Handles:
//! - Slot identification (A/B)
//! - Current/next/inactive slot tracking
//! - Boot metadata persistence
//! - Atomic cmdline.txt swap for boot selection
//! - Boot attempt counting and rollback logic

use balansir_common::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Slot identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn other(&self) -> Self {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    pub fn partition_number(&self) -> u8 {
        match self {
            Slot::A => 2, // mmcblk0p2
            Slot::B => 3, // mmcblk0p3
        }
    }

    pub fn kernel_filename(&self) -> String {
        format!("kernel-{}.img", self)
    }

    pub fn cmdline_filename(&self) -> String {
        format!("cmdline-{}.txt", self)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Slot::A => "A",
            Slot::B => "B",
        }
    }
}

impl std::fmt::Display for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Slot {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "a" => Ok(Slot::A),
            "b" => Ok(Slot::B),
            _ => Err(Error::Misconfiguration(format!("invalid slot: {s}"))),
        }
    }
}

/// Persistent boot metadata stored on the persistent partition.
///
/// This survives firmware updates and tracks boot state across reboots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootMetadata {
    /// Current active slot (the one that booted successfully).
    pub active_slot: Slot,

    /// Slot selected for next boot (may differ from active during update).
    pub next_slot: Slot,

    /// Number of remaining boot attempts for next_slot.
    /// Decrements on each boot failure.
    #[serde(default = "default_tries")]
    pub tries_remaining: u8,

    /// Boot state machine.
    #[serde(default)]
    pub state: BootState,

    /// Firmware version of active slot.
    pub active_version: String,

    /// Firmware version of next slot (pending).
    #[serde(default)]
    pub next_version: String,

    /// Last successful boot timestamp (Unix seconds).
    #[serde(default)]
    pub last_successful_boot: u64,

    /// Number of rollbacks performed.
    #[serde(default)]
    pub rollback_count: u32,

    /// Reason for last rollback.
    #[serde(default)]
    pub last_rollback_reason: String,

    /// Custom path for saving (test only).
    #[serde(skip)]
    pub test_save_path: Option<PathBuf>,
}

fn default_tries() -> u8 {
    3
}

/// Boot state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BootState {
    #[default]
    /// Normal operation, active_slot confirmed.
    Confirmed,
    /// Next boot will try next_slot (update pending).
    Pending,
    /// Currently trying next_slot, attempts remaining.
    Trying,
    /// Rollback in progress.
    RollingBack,
}

impl Default for BootMetadata {
    fn default() -> Self {
        Self {
            active_slot: Slot::A,
            next_slot: Slot::A,
            tries_remaining: 3,
            state: BootState::Confirmed,
            active_version: "unknown".into(),
            next_version: String::new(),
            last_successful_boot: 0,
            rollback_count: 0,
            last_rollback_reason: String::new(),
            test_save_path: None,
        }
    }
}

impl BootMetadata {
    /// Path to the metadata file on the persistent partition.
    const METADATA_PATH: &'static str = "/persistent/ota/boot-metadata.toml";

    /// Create metadata with a custom path (for testing).
    #[cfg(test)]
    pub fn new_test(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            info!("No OTA boot metadata found, creating default (Slot A)");
            let mut meta = Self::default();
            meta.test_save_path = Some(path.to_path_buf());
            meta.save()?;
            return Ok(meta);
        }

        let content = fs::read_to_string(path).map_err(|e| Error::Io(e))?;
        let mut meta: BootMetadata = toml::from_str(&content)
            .map_err(|e| Error::Misconfiguration(format!("parse boot metadata: {e}")))?;
        meta.test_save_path = Some(path.to_path_buf());
        debug!(
            "Loaded OTA boot metadata: active={} state={:?} tries={}",
            meta.active_slot, meta.state, meta.tries_remaining
        );
        Ok(meta)
    }

    /// Save metadata atomically to a custom path (for testing).
    #[cfg(test)]
    pub fn save_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::Io(e))?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| Error::Misconfiguration(format!("serialize boot metadata: {e}")))?;

        // Atomic write: write to temp then rename
        let tmp_path = path.with_extension("toml.tmp");
        fs::write(&tmp_path, content).map_err(|e| Error::Io(e))?;
        fs::rename(&tmp_path, path).map_err(|e| Error::Io(e))?;

        debug!(
            "Saved OTA boot metadata: active={} state={:?} tries={}",
            self.active_slot, self.state, self.tries_remaining
        );
        Ok(())
    }

    /// Load metadata from persistent storage.
    pub fn load() -> Result<Self> {
        let path = Path::new(Self::METADATA_PATH);
        if !path.exists() {
            info!("No OTA boot metadata found, creating default (Slot A)");
            let meta = Self::default();
            meta.save()?;
            return Ok(meta);
        }

        let content = fs::read_to_string(path).map_err(Error::Io)?;
        let meta: BootMetadata = toml::from_str(&content)
            .map_err(|e| Error::Misconfiguration(format!("parse boot metadata: {e}")))?;
        debug!(
            "Loaded OTA boot metadata: active={} state={:?} tries={}",
            meta.active_slot, meta.state, meta.tries_remaining
        );
        Ok(meta)
    }

    /// Save metadata atomically.
    pub fn save(&self) -> Result<()> {
        let path: &Path = if let Some(ref p) = self.test_save_path {
            p.as_ref()
        } else {
            Path::new(Self::METADATA_PATH)
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(Error::Io)?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| Error::Misconfiguration(format!("serialize boot metadata: {e}")))?;

        // Atomic write: write to temp then rename
        let tmp_path = path.with_extension("toml.tmp");
        fs::write(&tmp_path, content).map_err(Error::Io)?;
        fs::rename(&tmp_path, path).map_err(Error::Io)?;

        debug!(
            "Saved OTA boot metadata: active={} state={:?} tries={}",
            self.active_slot, self.state, self.tries_remaining
        );
        Ok(())
    }

    /// Get the current active slot.
    pub fn active_slot(&self) -> Slot {
        self.active_slot
    }

    /// Get the slot selected for next boot.
    pub fn next_slot(&self) -> Slot {
        self.next_slot
    }

    /// Check if an update is pending (next boot will try different slot).
    pub fn is_update_pending(&self) -> bool {
        self.state == BootState::Pending || self.state == BootState::Trying
    }

    /// Check if we're in the middle of trying a new slot.
    pub fn is_trying(&self) -> bool {
        self.state == BootState::Trying
    }

    /// Mark an update as prepared (next boot will try new slot).
    pub fn prepare_update(&mut self, new_slot: Slot, version: String) -> Result<()> {
        if new_slot == self.active_slot {
            return Err(Error::Misconfiguration("cannot update to same slot".into()));
        }
        self.next_slot = new_slot;
        self.next_version = version;
        self.state = BootState::Pending;
        self.tries_remaining = 3;
        self.save()
    }

    /// Called on boot: transition to Trying state if update was pending.
    pub fn on_boot(&mut self) -> Result<()> {
        if self.state == BootState::Pending {
            if self.next_slot == self.active_slot {
                // No actual slot change, just confirm
                self.state = BootState::Confirmed;
                self.tries_remaining = 3;
            } else {
                self.state = BootState::Trying;
                self.tries_remaining = self.tries_remaining.saturating_sub(1);
            }
            self.save()?;
        }
        Ok(())
    }

    /// Called when health check passes: confirm the new slot.
    pub fn confirm_boot(&mut self, version: String) -> Result<()> {
        if self.state == BootState::Trying {
            info!("Boot confirmed for slot {}", self.next_slot);
            self.active_slot = self.next_slot;
            self.active_version = version;
            self.next_slot = self.active_slot;
            self.next_version = String::new();
            self.state = BootState::Confirmed;
            self.tries_remaining = 3;
            self.last_successful_boot = current_timestamp();
            self.save()?;
        }
        Ok(())
    }

    /// Called when health check fails: decrement tries, rollback if exhausted.
    pub fn fail_boot(&mut self, reason: String) -> Result<bool> {
        if self.state != BootState::Trying {
            return Ok(false);
        }

        warn!(
            "Boot failed for slot {}: {} (tries remaining: {})",
            self.next_slot, reason, self.tries_remaining
        );

        if self.tries_remaining == 0 {
            // Exhausted attempts, rollback
            self.initiate_rollback(reason)?;
            return Ok(true);
        }

        self.tries_remaining = self.tries_remaining.saturating_sub(1);
        self.save()?;
        Ok(false)
    }

    /// Initiate rollback to previous slot.
    fn initiate_rollback(&mut self, reason: String) -> Result<()> {
        warn!(
            "Initiating rollback from {} to {}: {}",
            self.next_slot, self.active_slot, reason
        );

        self.state = BootState::RollingBack;
        self.next_slot = self.active_slot;
        self.next_version = self.active_version.clone();
        self.state = BootState::Confirmed;
        self.tries_remaining = 3;
        self.rollback_count += 1;
        self.last_rollback_reason = reason;
        self.save()
    }

    /// Force rollback (manual trigger).
    pub fn force_rollback(&mut self, reason: String) -> Result<()> {
        self.initiate_rollback(reason)
    }
}

/// Boot partition manager for cmdline.txt operations.
pub struct BootPartition {
    mount_point: PathBuf,
}

impl BootPartition {
    /// Create a new boot partition manager.
    pub fn new(mount_point: impl AsRef<Path>) -> Self {
        Self {
            mount_point: mount_point.as_ref().to_path_buf(),
        }
    }

    /// Get the path to cmdline.txt.
    pub fn cmdline_path(&self) -> PathBuf {
        self.mount_point.join("cmdline.txt")
    }

    /// Get the path to a slot-specific cmdline file.
    pub fn slot_cmdline_path(&self, slot: Slot) -> PathBuf {
        self.mount_point.join(slot.cmdline_filename())
    }

    /// Read current cmdline.txt.
    pub fn read_cmdline(&self) -> Result<String> {
        let path = self.cmdline_path();
        let content = fs::read_to_string(&path).map_err(Error::Io)?;
        Ok(content.trim().to_string())
    }

    /// Write cmdline.txt atomically.
    pub fn write_cmdline(&self, content: &str) -> Result<()> {
        let path = self.cmdline_path();
        let tmp = path.with_extension("txt.tmp");
        fs::write(&tmp, content).map_err(Error::Io)?;
        fs::rename(&tmp, path).map_err(Error::Io)?;
        // Sync to ensure it's on disk before reboot
        sync_all().map_err(Error::Io)?;
        Ok(())
    }

    /// Switch boot to a specific slot by updating cmdline.txt.
    ///
    /// This is atomic - the rename is atomic on POSIX.
    pub fn switch_to_slot(&self, slot: Slot) -> Result<()> {
        let slot_cmdline = self.slot_cmdline_path(slot);
        let content = fs::read_to_string(&slot_cmdline).map_err(Error::Io)?;
        self.write_cmdline(&content)?;
        info!("Switched boot to slot {}", slot);
        Ok(())
    }

    /// Ensure both slot cmdline files exist (create from template if needed).
    pub fn ensure_slot_cmdlines(&self, template_a: &str, template_b: &str) -> Result<()> {
        for (slot, template) in [(Slot::A, template_a), (Slot::B, template_b)] {
            let path = self.slot_cmdline_path(slot);
            if !path.exists() {
                fs::write(&path, template).map_err(Error::Io)?;
            }
        }
        Ok(())
    }

    /// Detect current boot slot from cmdline.
    pub fn detect_current_slot(&self) -> Result<Slot> {
        let cmdline = self.read_cmdline()?;
        if cmdline.contains("balansir_slot=B") || cmdline.contains("root=/dev/mmcblk0p3") {
            Ok(Slot::B)
        } else {
            Ok(Slot::A)
        }
    }
}

/// Sync all filesystems to ensure writes are flushed.
fn sync_all() -> std::io::Result<()> {
    unsafe { libc::sync() };
    Ok(())
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_meta() -> BootMetadata {
        let dir = tempdir().unwrap();
        BootMetadata::new_test(dir.path().join("boot-metadata.toml")).unwrap()
    }

    #[test]
    fn slot_other() {
        assert_eq!(Slot::A.other(), Slot::B);
        assert_eq!(Slot::B.other(), Slot::A);
    }

    #[test]
    fn slot_partition_number() {
        assert_eq!(Slot::A.partition_number(), 2);
        assert_eq!(Slot::B.partition_number(), 3);
    }

    #[test]
    fn boot_metadata_default() {
        let meta = BootMetadata::default();
        assert_eq!(meta.active_slot, Slot::A);
        assert_eq!(meta.state, BootState::Confirmed);
        assert_eq!(meta.tries_remaining, 3);
    }

    #[test]
    fn boot_metadata_prepare_update() {
        let mut meta = test_meta();
        meta.prepare_update(Slot::B, "0.6.0".into()).unwrap();
        assert_eq!(meta.next_slot, Slot::B);
        assert_eq!(meta.next_version, "0.6.0");
        assert_eq!(meta.state, BootState::Pending);
    }

    #[test]
    fn boot_metadata_confirm() {
        let mut meta = test_meta();
        meta.prepare_update(Slot::B, "0.6.0".into()).unwrap();
        meta.on_boot().unwrap(); // transition to Trying
        meta.confirm_boot("0.6.0".into()).unwrap();
        assert_eq!(meta.active_slot, Slot::B);
        assert_eq!(meta.active_version, "0.6.0");
        assert_eq!(meta.state, BootState::Confirmed);
    }

    #[test]
    fn boot_metadata_rollback() {
        let mut meta = test_meta();
        meta.prepare_update(Slot::B, "0.6.0".into()).unwrap();
        meta.on_boot().unwrap();
        meta.fail_boot("health check failed".into()).unwrap(); // try 1
        meta.fail_boot("health check failed".into()).unwrap(); // try 2
        let rolled = meta.fail_boot("health check failed".into()).unwrap(); // try 3 -> rollback
        assert!(rolled);
        assert_eq!(meta.active_slot, Slot::A);
        assert_eq!(meta.rollback_count, 1);
    }

    #[test]
    fn boot_partition_switch() {
        let dir = tempdir().unwrap();
        let boot = BootPartition::new(dir.path());

        // Create slot cmdline files
        fs::write(
            dir.path().join("cmdline-A.txt"),
            "root=/dev/mmcblk0p2 balansir_slot=A",
        )
        .unwrap();
        fs::write(
            dir.path().join("cmdline-B.txt"),
            "root=/dev/mmcblk0p3 balansir_slot=B",
        )
        .unwrap();

        boot.switch_to_slot(Slot::B).unwrap();
        let cmdline = boot.read_cmdline().unwrap();
        assert!(cmdline.contains("mmcblk0p3"));
        assert!(cmdline.contains("balansir_slot=B"));
    }
}
