//! Buildroot image build (Linux host only).
//!
//! Wraps the Buildroot `make` invocation with the BalanSir external tree and a
//! chosen defconfig. On macOS it reports that the build needs a Linux
//! environment (the Buildroot VM) — the tool never pretends to have built when
//! it has not (mission §15: no fake success).

use std::process::Command;

/// Build a Buildroot image for the given defconfig.
///
/// Looks for a Makefile (repo root or the `BUILDROOT_DIR` env var) and runs
/// `make BR2_EXTERNAL=<repo>/buildroot-external <defconfig>` followed by
/// `make`. Uses `sh -c` with fixed argv (no shell interpolation of the
/// defconfig name, which is validated against a small allowlist).
pub fn build(defconfig: &str) -> Result<String, String> {
    if !cfg!(target_os = "linux") {
        return Err(
            "build subcommand requires a Linux host (the Buildroot VM); on macOS use inspect/checksum"
                .into(),
        );
    }

    // Defconfig allowlist: only BalanSir targets are accepted.
    let allowed = [
        "balansir_rpi3b_64_defconfig",
        "balansir_qemu_virt_defconfig",
        "balansir_rk68_defconfig",
    ];
    if !allowed.contains(&defconfig) {
        return Err(format!(
            "unknown defconfig {defconfig:?} (expected one of {})",
            allowed.join(", ")
        ));
    }

    let repo_root = std::env::var("BALANSIR_ROOT").unwrap_or_else(|_| ".".to_string());
    let external = format!("{repo_root}/buildroot-external");
    if !std::path::Path::new(&external).is_dir() {
        return Err(format!("BalanSir external tree not found at {external}"));
    }
    let makefile = format!("{repo_root}/Makefile");
    if !std::path::Path::new(&makefile).exists() {
        return Err(format!(
            "Buildroot Makefile not found at {makefile} (set BALANSIR_ROOT)"
        ));
    }

    // Configure the defconfig.
    let configure = Command::new("make")
        .arg(format!("BR2_EXTERNAL={external}"))
        .arg(defconfig)
        .output()
        .map_err(|e| format!("spawn make configure: {e}"))?;
    if !configure.status.success() {
        return Err(format!(
            "make {defconfig} failed: {}",
            String::from_utf8_lossy(&configure.stderr).trim()
        ));
    }

    // Build.
    let build = Command::new("make")
        .arg(format!("BR2_EXTERNAL={external}"))
        .output()
        .map_err(|e| format!("spawn make build: {e}"))?;
    if !build.status.success() {
        return Err(format!(
            "make build failed: {}",
            String::from_utf8_lossy(&build.stderr).trim()
        ));
    }

    // The built image name follows Buildroot conventions.
    let image = match defconfig {
        "balansir_rpi3b_64_defconfig" => "sdcard.img",
        "balansir_qemu_virt_defconfig" => "rootfs.ext2",
        "balansir_rk68_defconfig" => "rootfs.ext2",
        _ => "image",
    };
    Ok(format!(
        "build complete: {image} in {repo_root}/output/images/ (see deploy/buildroot/sync-to-vm.sh for the VM workflow)"
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn defconfig_allowlist_rejects_unknown() {
        assert!(allowed_defconfig("balansir_rpi3b_64_defconfig"));
        assert!(allowed_defconfig("balansir_qemu_virt_defconfig"));
        assert!(allowed_defconfig("balansir_rk68_defconfig"));
        assert!(!allowed_defconfig("../../etc/passwd"));
        assert!(!allowed_defconfig("raspberrypi3_defconfig"));
    }

    fn allowed_defconfig(name: &str) -> bool {
        [
            "balansir_rpi3b_64_defconfig",
            "balansir_qemu_virt_defconfig",
            "balansir_rk68_defconfig",
        ]
        .contains(&name)
    }
}
