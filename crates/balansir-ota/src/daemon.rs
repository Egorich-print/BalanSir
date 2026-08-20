//! OTA installer: writes a signed-update image to the inactive A/B slot.
//!
//! The update loop (check/download/verify/prepare/post-boot/rollback) was
//! dead code — the CLI only installs an image provided by the operator. The
//! image is written with `dd` straight to the target partition; verification
//! is the operator's responsibility (the manifest/verifier path is unused).

use crate::slot::{self, BootPartition};
use balansir_common::{Error, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

/// OTA installer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaConfig {
    /// Boot partition mount point (for A/B cmdline files).
    #[serde(default = "default_boot_mount")]
    pub boot_mount: String,
}

fn default_boot_mount() -> String {
    "/boot".into()
}

/// OTA installer. Instantiated per `install` call; holds no long-lived state.
pub struct OtaDaemon {
    boot_partition: BootPartition,
    config: OtaConfig,
}

impl OtaDaemon {
    /// Create the installer and ensure A/B cmdline files exist on the boot
    /// partition (so both slots are bootable after an install).
    pub fn new(config: OtaConfig) -> Result<Self> {
        let cmdline_a = std::fs::read_to_string("/etc/balansir/cmdline-A.txt")
            .or_else(|_| std::fs::read_to_string(format!("{}/cmdline-A.txt", config.boot_mount)))
            .unwrap_or_else(|_| "root=/dev/mmcblk0p2 rootwait console=tty1 console=serial0,115200 loglevel=8 consoleblank=0 systemd.log_level=debug net.ifnames=0 biosdevname=0 balansir_slot=A".into());
        let cmdline_b = std::fs::read_to_string("/etc/balansir/cmdline-B.txt")
            .or_else(|_| std::fs::read_to_string(format!("{}/cmdline-B.txt", config.boot_mount)))
            .unwrap_or_else(|_| "root=/dev/mmcblk0p3 rootwait console=tty1 console=serial0,115200 loglevel=8 consoleblank=0 systemd.log_level=debug net.ifnames=0 biosdevname=0 balansir_slot=B".into());
        let boot_partition = BootPartition::new(&config.boot_mount);
        boot_partition.ensure_slot_cmdlines(&cmdline_a, &cmdline_b)?;

        Ok(Self {
            boot_partition,
            config,
        })
    }

    /// Access to the boot partition manager (for cmdline switching).
    pub fn boot_partition(&self) -> &BootPartition {
        &self.boot_partition
    }

    /// The installer configuration (boot mount point, etc.).
    pub fn config(&self) -> &OtaConfig {
        &self.config
    }

    /// Install the image to the inactive slot.
    pub async fn install(&self, image: Vec<u8>, target_slot: slot::Slot) -> Result<()> {
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

        // Verify the written image: hash the source image up front and compare
        // against the partition read-back. A mismatch is fatal (fail closed) —
        // an unverified slot must never be marked bootable.
        info!("Verifying written image...");
        let source_hash = sha256_hex(&image);
        let written_prefix_hash = hash_partition_prefix(&target_partition, image.len())?;
        if written_prefix_hash != source_hash {
            return Err(Error::Fatal(format!(
                "image verification failed: written {written_prefix_hash} != source {source_hash}"
            )));
        }

        info!("Installation complete on slot {target_slot} (verified {source_hash})");
        Ok(())
    }
}

/// Compute the hex sha256 of a byte slice (pure Rust, no shell).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Hash the first `len` bytes of a partition (read-back verification). The
/// slot partition is larger than the image, so only the image-length prefix is
/// compared — trailing filesystem padding must not be included.
fn hash_partition_prefix(partition: &str, len: usize) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(partition).map_err(Error::Io)?;
    use std::io::Read;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(buf.len());
        let n = file.read(&mut buf[..chunk]).map_err(Error::Io)?;
        if n == 0 {
            break; // EOF before the expected length — write is truncated
        }
        hasher.update(&buf[..n]);
        remaining -= n;
    }
    if remaining > 0 {
        return Err(Error::Fatal(format!(
            "image verification failed: partition shorter than image ({remaining} bytes missing)"
        )));
    }
    Ok(hex::encode(hasher.finalize()))
}
