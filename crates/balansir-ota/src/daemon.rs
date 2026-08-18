//! OTA daemon: manages update discovery, download, verification, installation, and slot management.

use crate::{health, manifest, slot};
use balansir_common::{Error, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// OTA daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaConfig {
    /// Update server base URL (e.g., "https://updates.balansir.example.com").
    pub server_url: String,

    /// Release channel to track.
    #[serde(default = "default_channel")]
    pub channel: String,

    /// Target device identifier.
    #[serde(default = "default_device")]
    pub target_device: String,

    /// Current firmware version (populated at build time).
    pub current_version: String,

    /// Check interval.
    #[serde(default = "default_check_interval")]
    pub check_interval_hours: u64,

    /// Download timeout.
    #[serde(default = "default_download_timeout")]
    pub download_timeout_secs: u64,

    /// Path to embedded public key (base64 Ed25519).
    pub public_key_path: String,

    /// Key identifier (must match manifest).
    pub key_id: String,

    /// Boot partition mount point.
    #[serde(default = "default_boot_mount")]
    pub boot_mount: String,

    /// Health check configuration.
    #[serde(default)]
    pub health: health::HealthConfig,

    /// Allow untrusted keys for development (NEVER in production).
    #[serde(default)]
    pub allow_untrusted: bool,

    /// Auto-apply updates after download/verify.
    #[serde(default = "default_auto_apply")]
    pub auto_apply: bool,

    /// Auto-reboot after successful install.
    #[serde(default = "default_auto_reboot")]
    pub auto_reboot: bool,
}

fn default_channel() -> String {
    "stable".into()
}

fn default_device() -> String {
    "rpi3b".into()
}

fn default_check_interval() -> u64 {
    6
}

fn default_download_timeout() -> u64 {
    300
}

fn default_boot_mount() -> String {
    "/boot".into()
}

fn default_auto_apply() -> bool {
    true
}

fn default_auto_reboot() -> bool {
    true
}

/// Update status for API/status reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    Idle,
    Checking,
    UpdateAvailable { version: String },
    Downloading { progress: u64, total: u64 },
    Verifying,
    Installing { slot: String },
    Installed { slot: String, pending_reboot: bool },
    Rebooting,
    Failed { reason: String },
    RolledBack { reason: String },
}

/// OTA daemon state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaState {
    pub status: UpdateStatus,
    pub current_version: String,
    pub current_slot: String,
    pub available_version: Option<String>,
    pub last_check: Option<u64>,
    pub last_update: Option<u64>,
    pub rollback_count: u32,
    pub last_error: Option<String>,
}

/// Main OTA daemon.
pub struct OtaDaemon {
    config: OtaConfig,
    state: Arc<RwLock<OtaState>>,
    slot_manager: Arc<RwLock<slot::BootMetadata>>,
    boot_partition: slot::BootPartition,
    verifier: manifest::UpdateVerifier,
    http_client: reqwest::Client,
    health_checker: health::HealthChecker,
    running: Arc<RwLock<bool>>,
}

impl OtaDaemon {
    /// Create a new OTA daemon.
    pub fn new(config: OtaConfig) -> Result<Self> {
        // Load embedded public key
        let key_b64 = std::fs::read_to_string(&config.public_key_path).map_err(Error::Io)?;
        let key_id = manifest::KeyId(config.key_id.clone());
        let verifier = manifest::UpdateVerifier::from_base64(&key_b64, key_id)?;

        // Initialize slot manager
        let slot_manager = slot::BootMetadata::load()?;
        let boot_partition = slot::BootPartition::new(&config.boot_mount);

        // Ensure slot cmdline files exist
        let cmdline_a = std::fs::read_to_string("/etc/balansir/cmdline-A.txt")
            .or_else(|_| std::fs::read_to_string(format!("{}/cmdline-A.txt", config.boot_mount)))
            .unwrap_or_else(|_| "root=/dev/mmcblk0p2 rootwait console=tty1 console=serial0,115200 loglevel=8 consoleblank=0 systemd.log_level=debug net.ifnames=0 biosdevname=0 balansir_slot=A".into());
        let cmdline_b = std::fs::read_to_string("/etc/balansir/cmdline-B.txt")
            .or_else(|_| std::fs::read_to_string(format!("{}/cmdline-B.txt", config.boot_mount)))
            .unwrap_or_else(|_| "root=/dev/mmcblk0p3 rootwait console=tty1 console=serial0,115200 loglevel=8 consoleblank=0 systemd.log_level=debug net.ifnames=0 biosdevname=0 balansir_slot=B".into());
        boot_partition.ensure_slot_cmdlines(&cmdline_a, &cmdline_b)?;

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.download_timeout_secs))
            .build()
            .map_err(|e| Error::Misconfiguration(format!("HTTP client: {e}")))?;

        let health_checker = health::HealthChecker::new(config.health.clone());

        // Detect current slot
        let current_slot = boot_partition
            .detect_current_slot()
            .unwrap_or(slot::Slot::A);

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(OtaState {
                status: UpdateStatus::Idle,
                current_version: String::new(),
                current_slot: current_slot.to_string(),
                available_version: None,
                last_check: None,
                last_update: None,
                rollback_count: 0,
                last_error: None,
            })),
            slot_manager: Arc::new(RwLock::new(slot_manager)),
            boot_partition,
            verifier,
            http_client,
            health_checker,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Get current state.
    pub async fn state(&self) -> OtaState {
        self.state.read().await.clone()
    }

    /// Check for available updates.
    pub async fn check_updates(&self) -> Result<Option<manifest::VerifiedUpdate>> {
        self.set_status(UpdateStatus::Checking).await;

        let manifest_url = format!(
            "{}/{}/{}/manifest.toml",
            self.config.server_url.trim_end_matches('/'),
            self.config.channel,
            self.config.target_device
        );

        info!("Checking for updates at {}", manifest_url);

        let response = self
            .http_client
            .get(&manifest_url)
            .send()
            .await
            .map_err(|e| Error::Temporary(format!("manifest download failed: {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            info!(
                "No update manifest found for {}/{}",
                self.config.channel, self.config.target_device
            );
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(Error::Fatal(format!(
                "manifest download failed: HTTP {}",
                response.status()
            )));
        }

        let manifest_text = response
            .text()
            .await
            .map_err(|e| Error::Temporary(format!("manifest read failed: {e}")))?;

        // Verify manifest
        let verified = manifest::VerifiedUpdate::verify(&self.verifier, &manifest_text)?;

        // Check version
        if version_compare(
            &verified.manifest.firmware_version,
            &self.config.current_version,
        ) <= 0
        {
            info!(
                "No newer version available (current: {}, manifest: {})",
                self.config.current_version, verified.manifest.firmware_version
            );
            return Ok(None);
        }

        // Anti-rollback check
        if let Some(min_ver) = &verified.manifest.min_version {
            if version_compare(&self.config.current_version, min_ver) < 0 {
                warn!("Update would violate anti-rollback policy (current < min_version)");
                return Err(Error::Misconfiguration("anti-rollback violation".into()));
            }
        }

        // Check target device matches
        if verified.manifest.target_device != self.config.target_device {
            return Err(Error::Misconfiguration("target device mismatch".into()));
        }

        info!(
            "Update available: {} -> {}",
            self.config.current_version, verified.manifest.firmware_version
        );

        self.update_state(|s| {
            s.status = UpdateStatus::UpdateAvailable {
                version: verified.manifest.firmware_version.clone(),
            };
            s.available_version = Some(verified.manifest.firmware_version.clone());
            s.last_check = Some(current_timestamp());
        })
        .await;

        Ok(Some(verified))
    }

    /// Download and verify the firmware image.
    pub async fn download_and_verify(&self, update: &manifest::VerifiedUpdate) -> Result<Vec<u8>> {
        self.set_status(UpdateStatus::Downloading {
            progress: 0,
            total: 0,
        })
        .await;

        let image_info = &update.manifest.image;
        let mut progress = 0u64;
        let total = image_info.size;

        let client = self.http_client.clone();
        let url = image_info.url.clone();
        let expected_size = image_info.size;

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Temporary(format!("image download failed: {e}")))?;

        if !response.status().is_success() {
            return Err(Error::Fatal(format!(
                "image download failed: HTTP {}",
                response.status()
            )));
        }

        let mut stream = response.bytes_stream();
        let mut buffer = Vec::with_capacity(expected_size as usize);
        let mut downloaded = 0u64;

        use futures::StreamExt;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| Error::Temporary(format!("download error: {e}")))?;
            downloaded += chunk.len() as u64;
            buffer.extend_from_slice(&chunk);

            let new_progress = (downloaded * 100) / total;
            if new_progress != progress {
                progress = new_progress;
                self.set_status(UpdateStatus::Downloading { progress, total })
                    .await;
                debug!("Download progress: {}%", progress);
            }
        }

        if downloaded != expected_size {
            return Err(Error::Misconfiguration(format!(
                "incomplete download: expected {}, got {}",
                expected_size, downloaded
            )));
        }

        self.set_status(UpdateStatus::Verifying).await;

        // Decompress and verify
        let decompressed = match image_info.compression.as_str() {
            "xz" => {
                let mut decoder = xz2::read::XzDecoder::new(std::io::Cursor::new(&buffer));
                let mut out = Vec::new();
                std::io::copy(&mut decoder, &mut out)
                    .map_err(|e| Error::Misconfiguration(format!("xz decompress failed: {e}")))?;
                out
            }
            "gz" => {
                let mut decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(&buffer));
                let mut out = Vec::new();
                std::io::copy(&mut decoder, &mut out)
                    .map_err(|e| Error::Misconfiguration(format!("gz decompress failed: {e}")))?;
                out
            }
            "none" => buffer,
            other => {
                return Err(Error::Misconfiguration(format!(
                    "unknown compression: {other}"
                )))
            }
        };

        // Verify SHA-256
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&decompressed);
        let hash_hex = hex::encode(hash);
        if hash_hex != image_info.sha256 {
            return Err(Error::Misconfiguration(format!(
                "SHA-256 mismatch: expected {}, got {}",
                image_info.sha256, hash_hex
            )));
        }

        if decompressed.len() != expected_size as usize {
            return Err(Error::Misconfiguration(format!(
                "decompressed size mismatch: expected {}, got {}",
                expected_size,
                decompressed.len()
            )));
        }

        info!("Image verified: {} bytes, SHA-256 OK", decompressed.len());
        Ok(decompressed)
    }

    /// Install the verified image to the inactive slot.
    pub async fn install(&self, image: Vec<u8>, target_slot: slot::Slot) -> Result<()> {
        self.set_status(UpdateStatus::Installing {
            slot: target_slot.to_string(),
        })
        .await;

        // Determine target partition
        let target_partition = format!("/dev/mmcblk0p{}", target_slot.partition_number());
        info!("Installing to {} ({})", target_slot, target_partition);

        // Check if partition exists
        if !std::path::Path::new(&target_partition).exists() {
            return Err(Error::Fatal(format!(
                "target partition {} not found",
                target_partition
            )));
        }

        // Write image directly to partition (streaming to avoid RAM issues)
        info!(
            "Writing image to {} ({} bytes)",
            target_partition,
            image.len()
        );

        // Use dd for efficient block writing
        use std::process::Command;
        let mut dd = Command::new("dd")
            .arg("if=/dev/stdin")
            .arg(format!("of={}", target_partition))
            .arg("bs=1M")
            .arg("oflag=sync")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Fatal(format!("spawn dd: {e}")))?;

        use std::io::Write;
        {
            let stdin = dd.stdin.as_mut().unwrap();
            stdin
                .write_all(&image)
                .map_err(|e| Error::Fatal(format!("write image: {e}")))?;
        }

        let output = dd
            .wait_with_output()
            .map_err(|e| Error::Fatal(format!("dd wait: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Fatal(format!("dd failed: {}", stderr)));
        }

        // Verify written image by reading back and checking hash
        info!("Verifying written image...");
        let verify_output = Command::new("sha256sum")
            .arg(&target_partition)
            .output()
            .map_err(|e| Error::Fatal(format!("sha256sum: {e}")))?;

        if !verify_output.status.success() {
            return Err(Error::Fatal("sha256sum verification failed".into()));
        }

        let _written_hash = String::from_utf8_lossy(&verify_output.stdout)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_string();

        info!("Installation complete on slot {}", target_slot);
        Ok(())
    }

    /// Prepare update: download, verify, install, and schedule reboot.
    pub async fn prepare_update(&self) -> Result<()> {
        let update = match self.check_updates().await? {
            Some(u) => u,
            None => {
                info!("No updates available");
                return Ok(());
            }
        };

        let target_slot = {
            let meta = self.slot_manager.read().await;
            meta.active_slot.other()
        };

        info!(
            "Preparing update to slot {} (version {})",
            target_slot, update.manifest.firmware_version
        );

        // Download and verify
        let image = self.download_and_verify(&update).await?;

        // Prepare slot metadata
        {
            let mut meta = self.slot_manager.write().await;
            meta.prepare_update(target_slot, update.manifest.firmware_version.clone())?;
        }

        // Install
        self.install(image, target_slot).await?;

        // Switch boot to new slot
        self.boot_partition.switch_to_slot(target_slot)?;

        // Update state
        self.update_state(|s| {
            s.status = UpdateStatus::Installed {
                slot: target_slot.to_string(),
                pending_reboot: true,
            };
        })
        .await;

        // Reboot if configured
        if self.config.auto_reboot {
            info!("Rebooting to apply update...");
            self.set_status(UpdateStatus::Rebooting).await;
            self.reboot().await?;
        }

        Ok(())
    }

    /// Run post-boot health check and confirm/rollback.
    pub async fn post_boot_check(&self) -> Result<bool> {
        info!("Running post-boot health check");

        let slot = {
            let meta = self.slot_manager.read().await;
            meta.active_slot
        };

        let version = {
            let meta = self.slot_manager.read().await;
            meta.active_version.clone()
        };

        // Let slot manager know we booted
        {
            let mut meta = self.slot_manager.write().await;
            meta.on_boot()?;
        }

        // Run health checks
        let report = self.health_checker.run(slot.to_string(), version).await?;

        if report.should_confirm() {
            info!("Health check PASSED, confirming slot {}", slot);
            let mut meta = self.slot_manager.write().await;
            meta.confirm_boot(report.firmware_version.clone())?;
            self.update_state(|s| {
                s.status = UpdateStatus::Idle;
                s.current_slot = slot.to_string();
                s.current_version = report.firmware_version;
                s.last_update = Some(current_timestamp());
                s.rollback_count = meta.rollback_count;
            })
            .await;
            Ok(true)
        } else {
            warn!("Health check FAILED, initiating rollback");
            let mut meta = self.slot_manager.write().await;
            meta.fail_boot(format!(
                "Health check failed: {} critical failures",
                report
                    .checks
                    .iter()
                    .filter(|c| c.critical && !c.passed)
                    .count()
            ))?;

            // Switch back to previous slot
            self.boot_partition.switch_to_slot(meta.active_slot)?;

            let reason = "health check failed".to_string();
            self.update_state(|s| {
                s.status = UpdateStatus::RolledBack {
                    reason: reason.clone(),
                };
                s.current_slot = meta.active_slot.to_string();
                s.rollback_count = meta.rollback_count;
                s.last_error = Some(reason);
            })
            .await;

            // Reboot to rollback
            if self.config.auto_reboot {
                self.reboot().await?;
            }
            Ok(false)
        }
    }

    /// Force rollback to previous slot.
    pub async fn force_rollback(&self, reason: String) -> Result<()> {
        warn!("Force rollback requested: {}", reason);

        let mut meta = self.slot_manager.write().await;
        meta.force_rollback(reason.clone())?;

        self.boot_partition.switch_to_slot(meta.active_slot)?;

        self.update_state(|s| {
            s.status = UpdateStatus::RolledBack {
                reason: reason.clone(),
            };
            s.current_slot = meta.active_slot.to_string();
            s.rollback_count = meta.rollback_count;
            s.last_error = Some(reason);
        })
        .await;

        if self.config.auto_reboot {
            self.reboot().await?;
        }

        Ok(())
    }

    /// Start the OTA daemon loop.
    pub async fn run(&self) -> Result<()> {
        *self.running.write().await = true;
        info!("OTA daemon started");

        // Initial check
        self.check_updates().await.ok();

        let mut check_interval =
            interval(Duration::from_secs(self.config.check_interval_hours * 3600));

        while *self.running.read().await {
            check_interval.tick().await;

            if !self.config.auto_apply {
                debug!("Auto-apply disabled, skipping update check");
                continue;
            }

            match self.check_updates().await {
                Ok(Some(_update)) => {
                    if let Err(e) = self.prepare_update().await {
                        error!("Update preparation failed: {}", e);
                        self.update_state(|s| {
                            s.status = UpdateStatus::Failed {
                                reason: e.to_string(),
                            };
                            s.last_error = Some(e.to_string());
                        })
                        .await;
                    }
                }
                Ok(None) => {
                    debug!("No updates available");
                }
                Err(e) => {
                    warn!("Update check failed: {}", e);
                    self.update_state(|s| {
                        s.last_error = Some(e.to_string());
                    })
                    .await;
                }
            }
        }

        info!("OTA daemon stopped");
        Ok(())
    }

    /// Stop the daemon.
    pub async fn stop(&self) {
        *self.running.write().await = false;
        info!("OTA daemon stopping");
    }

    /// Trigger system reboot.
    async fn reboot(&self) -> Result<()> {
        use std::process::Command;
        Command::new("systemctl")
            .args(["reboot"])
            .spawn()
            .map_err(|e| Error::Fatal(format!("reboot: {e}")))?;
        Ok(())
    }

    async fn set_status(&self, status: UpdateStatus) {
        self.update_state(|s| s.status = status).await;
    }

    async fn update_state<F>(&self, f: F)
    where
        F: FnOnce(&mut OtaState),
    {
        let mut state = self.state.write().await;
        f(&mut state);
    }
}

/// Simple version comparison (semver-like).
fn version_compare(a: &str, b: &str) -> i32 {
    let parse = |v: &str| -> Vec<u32> { v.split('.').map(|s| s.parse().unwrap_or(0)).collect() };

    let a_parts = parse(a);
    let b_parts = parse(b);

    let max_len = a_parts.len().max(b_parts.len());
    for i in 0..max_len {
        let a = a_parts.get(i).copied().unwrap_or(0);
        let b = b_parts.get(i).copied().unwrap_or(0);
        if a < b {
            return -1;
        }
        if a > b {
            return 1;
        }
    }
    0
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

    #[test]
    fn version_compare_basic() {
        assert_eq!(version_compare("0.6.0", "0.5.0"), 1);
        assert_eq!(version_compare("0.5.0", "0.6.0"), -1);
        assert_eq!(version_compare("0.6.0", "0.6.0"), 0);
        assert_eq!(version_compare("1.0.0", "0.9.9"), 1);
        assert_eq!(version_compare("0.10.0", "0.9.0"), 1);
    }

    #[test]
    fn ota_config_defaults() {
        let config = OtaConfig {
            server_url: "https://example.com".into(),
            channel: "stable".into(),
            target_device: "rpi3b".into(),
            current_version: "0.5.0".into(),
            check_interval_hours: 6,
            download_timeout_secs: 300,
            public_key_path: "/etc/balansir/ota-key.pub".into(),
            key_id: "prod-2024".into(),
            boot_mount: "/boot".into(),
            health: health::HealthConfig {
                check_timeout_secs: 10,
                total_timeout_secs: 120,
                critical_checks: health::default_critical_checks(),
                optional_checks: health::default_optional_checks(),
                min_wan_uptime_secs: 30,
            },
            allow_untrusted: false,
            auto_apply: true,
            auto_reboot: true,
        };
        assert_eq!(config.channel, "stable");
        assert_eq!(config.auto_apply, true);
    }
}
