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
use balansir_ota::slot::{BootMetadata, Slot};

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
    let version = env!("CARGO_PKG_VERSION").to_string();
    meta.confirm_boot(version)
        .map_err(|e| format!("confirm: {e}"))?;
    meta.save().map_err(|e| format!("save: {e}"))?;
    println!("Slot {} confirmed", meta.active_slot());
    Ok(())
}

fn cmd_rollback() -> Result<(), String> {
    let mut meta = load_metadata()?;
    meta.force_rollback("manual rollback via CLI".to_string())
        .map_err(|e| format!("rollback: {e}"))?;
    meta.save().map_err(|e| format!("save: {e}"))?;
    println!("Rolled back to slot {}", meta.active_slot());
    println!("Reboot required to apply");
    Ok(())
}

async fn cmd_update(image_path: &str, config: &OtaConfig) -> Result<(), String> {
    let image = std::fs::read(image_path).map_err(|e| format!("read image: {e}"))?;
    let mut meta = load_metadata()?;
    let inactive = meta.next_slot();
    println!("Installing to slot {inactive} ({} bytes)...", image.len());
    let daemon = OtaDaemon::new(config.clone()).map_err(|e| format!("init OTA daemon: {e}"))?;
    daemon
        .install(image, inactive)
        .await
        .map_err(|e| format!("install failed: {e}"))?;
    println!("Image installed to slot {inactive}");
    println!("Reboot required to activate");
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
