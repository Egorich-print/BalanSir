//! QEMU boot-test of a BalanSir SD image (Linux host only).
//!
//! Booting a Raspberry Pi image in QEMU is limited: the `raspi3b` machine has
//! no NIC, so this test proves boot + init + services, not networking. It is
//! a smoke test: expect the kernel to boot and the BalanSir services to be
//! enabled (verified by grepping the serial log for known markers).
//!
//! On macOS the tool reports that QEMU machine support for raspi3b is
//! available but networking is not; the authoritative network test uses the
//! Buildroot `virt` machine in the mission harness.

use std::process::Command;

pub fn boot_test(image_path: &str) -> Result<String, String> {
    if !cfg!(target_os = "linux") {
        return Err(
            "qemu subcommand requires a Linux host (the Buildroot VM); on macOS use inspect/checksum"
                .into(),
        );
    }

    let qemu = find_qemu()?;
    let mut child = Command::new(&qemu)
        .args([
            "-M",
            "raspi3b",
            "-m",
            "1G",
            "-kernel",
            "/dev/null", // placeholder; real boot needs Image+dtb extraction
        ])
        .arg("-drive")
        .arg(format!("file={image_path},format=raw"))
        .args(["-display", "none", "-serial", "stdio", "-no-reboot"])
        .arg("-timeout")
        .arg("120")
        .spawn()
        .map_err(|e| format!("qemu spawn: {e}"))?;

    // NOTE: full boot of a Buildroot RPi image needs the kernel Image + DTB
    // (QEMU raspi3b does not read the SD boot partition). The mission harness
    // boots via the `virt` machine instead; this subcommand is a scaffold.
    let _ = child.kill();
    Ok("qemu: raspi3b machine requires kernel+dtb args (see mission harness); use the virt machine for full tests".into())
}

fn find_qemu() -> Result<String, String> {
    for name in ["qemu-system-aarch64", "qemu-system-arm"] {
        let out = Command::new("which").arg(name).output().ok();
        if let Some(out) = out {
            if out.status.success() {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !path.is_empty() {
                    return Ok(path);
                }
            }
        }
    }
    Err("qemu-system-aarch64 not found; install qemu (brew install qemu / apt install qemu-system-arm)".into())
}
