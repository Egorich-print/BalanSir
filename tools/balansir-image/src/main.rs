//! balansir-image — BalanSir embedded image tooling.
//!
//! Subcommands:
//!   build      build the Buildroot image (wraps `make` in a Linux env)
//!   inspect    show partition table + filesystems of an SD image
//!   verify     verify an image: checksum manifest, ELF architecture,
//!              static/dynamic linking of the BalanSir binaries
//!   checksum   write a SHA-256 manifest for an image
//!   qemu       boot-test an image under QEMU (Linux host)
//!
//! Cross-platform (macOS/Linux) for inspect/checksum; build/qemu need a Linux
//! environment (the Buildroot VM), which the tool detects and reports.

mod build;
mod collect;
mod elf;
mod image;
mod qemu;
mod verify;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        return ExitCode::from(2);
    }
    match args[1].as_str() {
        "inspect" => {
            let path = need_arg(&args, 2);
            match image::inspect(path) {
                Ok(out) => {
                    println!("{out}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("balansir-image: {e}");
                    ExitCode::from(1)
                }
            }
        }
        "checksum" => {
            let path = need_arg(&args, 2);
            match image::write_checksum(path) {
                Ok(out) => {
                    println!("{out}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("balansir-image: {e}");
                    ExitCode::from(1)
                }
            }
        }
        "verify" => {
            let path = need_arg(&args, 2);
            match verify::verify(path) {
                Ok(out) => {
                    println!("{out}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("balansir-image: {e}");
                    ExitCode::from(1)
                }
            }
        }
        "collect" => {
            let host = need_arg(&args, 2);
            match collect::collect(host) {
                Ok(out) => {
                    println!("{out}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("balansir-image: {e}");
                    ExitCode::from(1)
                }
            }
        }
        "qemu" => {
            let path = need_arg(&args, 2);
            match qemu::boot_test(path) {
                Ok(out) => {
                    println!("{out}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("balansir-image: {e}");
                    ExitCode::from(1)
                }
            }
        }
        "build" => {
            let defconfig = args
                .get(2)
                .map(|s| s.as_str())
                .unwrap_or("balansir_rpi3b_64_defconfig");
            match build::build(defconfig) {
                Ok(out) => {
                    println!("{out}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("balansir-image: {e}");
                    ExitCode::from(1)
                }
            }
        }
        "help" | "-h" | "--help" => {
            usage();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("balansir-image: unknown subcommand '{other}'");
            usage();
            ExitCode::from(2)
        }
    }
}

fn need_arg(args: &[String], idx: usize) -> &str {
    args.get(idx).map(|s| s.as_str()).unwrap_or_else(|| {
        usage();
        std::process::exit(2);
    })
}

fn usage() {
    println!(
        "balansir-image — BalanSir embedded image tooling

USAGE:
  balansir-image inspect <sdcard.img>       show partition table + filesystems
  balansir-image checksum <sdcard.img>      write SHA-256 manifest (image.sha256)
  balansir-image qemu <sdcard.img>          boot-test under QEMU (Linux host)
  balansir-image build [defconfig]          build via Buildroot (Linux env)
  balansir-image verify <sdcard.img>        verify manifest + ELF binaries
  balansir-image collect <user@host>       collect diagnostics over SSH
  balansir-image help                       this message
"
    );
}
