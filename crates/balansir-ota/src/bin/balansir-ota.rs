//! BalanSir OTA daemon — standalone binary.
//!
//! Manages signed OTA updates with A/B slot management, atomic boot selection,
//! post-boot health checks, and automatic rollback.
//!
//! Usage:
//!   balansir-ota update <image-path>   # install image to inactive slot
//!   balansir-ota status                # show current slot and health
//!   balansir-ota rollback              # force rollback to previous slot
//!   balansir-ota boot-confirm          # confirm current slot is healthy

use balansir_ota::daemon::{OtaConfig, OtaDaemon};
use balansir_ota::slot::{BootMetadata, BootPartition};

fn usage() {
    eprintln!("Usage: balansir-ota <command>");
    eprintln!("Commands:");
    eprintln!("  update <image-path>   Install image to inactive slot");
    eprintln!("  status                Show current slot, health, rollback count");
    eprintln!("  rollback              Force rollback to previous slot");
    eprintln!("  boot-confirm          Confirm current slot is healthy");
}

fn load_config() -> Result<OtaConfig, String> {
    let path = std::env::var("BALANSIR_OTA_CONFIG")
        .unwrap_or_else(|_| "/etc/balansir/ota.toml".to_string());
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
    toml::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))
}

fn load_metadata() -> Result<BootMetadata, String> {
    BootMetadata::load().map_err(|e| format!("load metadata: {e}"))
}

fn cmd_status() -> Result<(), String> {
    let meta = load_metadata()?;
    println!("Active slot:       {}", meta.active_slot());
    println!("State:             {:?}", meta.state);
    println!("Rollback count:    {}", meta.rollback_count);
    if !meta.last_rollback_reason.is_empty() {
        println!("Last rollback:     {}", meta.last_rollback_reason);
    }
    Ok(())
}

fn cmd_boot_confirm() -> Result<(), String> {
    let mut meta = load_metadata()?;
    // Only meaningful when an update is pending/trying: confirm the slot that
    // actually booted. When state is Confirmed this is a no-op (idempotent).
    let boot = BootPartition::new(boot_mount());
    let booted = boot.detect_current_slot().unwrap_or(meta.active_slot());
    let version = env!("CARGO_PKG_VERSION").to_string();
    // If the booted slot differs from the confirmed active slot, promote it.
    if booted != meta.active_slot() {
        meta.active_slot = booted;
        meta.active_version = version;
        meta.state = balansir_ota::slot::BootState::Confirmed;
        meta.tries_remaining = 3;
        meta.save().map_err(|e| format!("save: {e}"))?;
        println!("Boot confirmed for slot {}", meta.active_slot());
    } else {
        // Same slot: normal confirm path.
        meta.confirm_boot(version)
            .map_err(|e| format!("confirm: {e}"))?;
        meta.save().map_err(|e| format!("save: {e}"))?;
        println!("Slot {} confirmed", meta.active_slot());
    }
    Ok(())
}

fn cmd_rollback() -> Result<(), String> {
    let mut meta = load_metadata()?;
    let target = meta.active_slot();
    meta.force_rollback("manual rollback via CLI".to_string())
        .map_err(|e| format!("rollback: {e}"))?;
    // Roll back the boot cmdline to the confirmed slot and make the next boot
    // land there (fail-safe: the slot marked active is what we boot).
    let boot = BootPartition::new(boot_mount());
    boot.switch_to_slot(target)
        .map_err(|e| format!("switch boot slot: {e}"))?;
    meta.save().map_err(|e| format!("save: {e}"))?;
    println!("Rolled back to slot {}", target);
    println!("Reboot required to apply");
    Ok(())
}

fn boot_mount() -> String {
    std::env::var("BALANSIR_BOOT_MOUNT").unwrap_or_else(|_| "/boot".to_string())
}

async fn cmd_update(image_path: &str, config: &OtaConfig) -> Result<(), String> {
    let image = std::fs::read(image_path).map_err(|e| format!("read image: {e}"))?;
    let mut meta = load_metadata()?;
    // The target slot is the one NOT currently active (mission §13: install to
    // the free slot, never the running one).
    let inactive = meta.active_slot().other();
    println!("Installing to slot {inactive} ({} bytes)...", image.len());
    let daemon = OtaDaemon::new(config.clone()).map_err(|e| format!("init OTA daemon: {e}"))?;
    daemon
        .install(image, inactive)
        .await
        .map_err(|e| format!("install failed: {e}"))?;
    // Mark the slot for boot on the next reboot: switch the boot cmdline and
    // record the Pending state so `boot-confirm`/`rollback` have a real
    // decision to make.
    let boot = daemon.boot_partition();
    boot.switch_to_slot(inactive)
        .map_err(|e| format!("switch boot slot: {e}"))?;
    meta.next_slot = inactive;
    meta.state = balansir_ota::slot::BootState::Pending;
    meta.tries_remaining = 3;
    meta.save().map_err(|e| format!("save metadata: {e}"))?;
    println!("Image installed to slot {inactive}");
    println!("Boot switched to slot {inactive}; reboot required to activate");
    println!("After boot, run `balansir-ota boot-confirm` to confirm the slot");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(1);
    }

    let result = match args[1].as_str() {
        "status" => cmd_status(),
        "boot-confirm" => cmd_boot_confirm(),
        "rollback" => cmd_rollback(),
        "update" => {
            if args.len() < 3 {
                eprintln!("Usage: balansir-ota update <image-path>");
                std::process::exit(1);
            }
            match load_config() {
                Ok(config) => cmd_update(&args[2], &config).await,
                Err(e) => Err(format!("config error: {e}")),
            }
        }
        _ => {
            usage();
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
