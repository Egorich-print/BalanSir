//! `balansir-image verify`: checksum manifest verification + ELF inspection.

use crate::elf;
use crate::image::sha256;

/// Verify an image: the `.sha256` manifest must match, and any ELF files
/// given as extra args are described (architecture + linking mode).
pub fn verify(image_path: &str) -> Result<String, String> {
    let data = std::fs::read(image_path).map_err(|e| format!("read {image_path}: {e}"))?;
    let digest = sha256(&data);

    let manifest_path = format!("{image_path}.sha256");
    let manifest = std::fs::read_to_string(&manifest_path).map_err(|_| {
        format!("{manifest_path} missing; run: balansir-image checksum {image_path}")
    })?;

    let mut ok = false;
    let mut reported = String::new();
    for line in manifest.lines() {
        let mut parts = line.split_whitespace();
        let expected = parts.next().unwrap_or("");
        let _filename = parts.next().unwrap_or("");
        if expected == digest {
            ok = true;
        }
        reported.push_str(line);
        reported.push('\n');
    }

    if !ok {
        return Err(format!(
            "checksum MISMATCH for {image_path}\n  manifest: {reported}  actual: {digest}"
        ));
    }

    let mut out = String::new();
    out.push_str(&format!("checksum OK: {image_path} -> {digest}\n"));

    // Extra args: ELF files to describe.
    let extra: Vec<String> = std::env::args().skip(3).collect();
    if !extra.is_empty() {
        out.push_str("ELF inspection:\n");
        for f in &extra {
            let data = std::fs::read(f).map_err(|e| format!("read {f}: {e}"))?;
            let info = elf::parse_elf(&data);
            out.push_str(&format!("  {f}: {}\n", info.describe()));
        }
    } else {
        out.push_str("(pass ELF paths after the image to inspect binaries)\n");
    }
    Ok(out)
}
