//! Image inspection: partition table (MBR) + filesystem offsets, without
//! external tools or root. Pure Rust over the raw image file.

use std::fmt::Write as _;
use std::path::Path;

const SECTOR: u64 = 512;

/// Partition table entry from the MBR.
#[derive(Debug, Clone, Copy)]
struct MbrEntry {
    bootable: bool,
    partition_type: u8,
    start_sector: u32,
    sector_count: u32,
}

/// Read the MBR partition table (4 primary entries).
fn read_mbr(file: &[u8]) -> Result<Vec<MbrEntry>, String> {
    if file.len() < 512 {
        return Err("image too small for an MBR".into());
    }
    let mut entries = Vec::new();
    // Partition table starts at offset 0x1BE (446), 4 entries x 16 bytes.
    for i in 0..4 {
        let off = 0x1BE + i * 16;
        let status = file[off];
        let ptype = file[off + 4];
        let start = u32::from_le_bytes(file[off + 8..off + 12].try_into().unwrap());
        let count = u32::from_le_bytes(file[off + 12..off + 16].try_into().unwrap());
        if ptype != 0 {
            entries.push(MbrEntry {
                bootable: status == 0x80,
                partition_type: ptype,
                start_sector: start,
                sector_count: count,
            });
        }
    }
    if entries.is_empty() {
        return Err("no MBR partitions found".into());
    }
    Ok(entries)
}

/// Detect the filesystem type at an offset by magic bytes.
fn fs_type(file: &[u8], offset: u64) -> &'static str {
    let o = offset as usize;
    if file.len() < o + 8 {
        return "unknown";
    }
    // FAT32: 0xEB 0x58 0x90 or 0xEB 0x76 0x90 at boot sector.
    if file[o] == 0xEB && (file[o + 2] == 0x90 || file[o + 2] == 0x53) {
        return "vfat/fat32";
    }
    // ext4/ext2: 0x53 0xEF at offset 0x438.
    if file.len() >= o + 0x43A && file[o + 0x438] == 0x53 && file[o + 0x439] == 0xEF {
        let feat = if file.len() >= o + 0x464 {
            u32::from_le_bytes(file[o + 0x460..o + 0x464].try_into().unwrap())
        } else {
            0
        };
        return if feat & 4 != 0 { "ext4" } else { "ext2/ext3" };
    }
    "unknown"
}

fn type_name(t: u8) -> &'static str {
    match t {
        0x0C | 0x0B | 0x0E => "FAT32/LBA",
        0x83 => "Linux",
        0x82 => "Linux swap",
        0xEE => "GPT protective",
        _ => "Linux/other",
    }
}

/// Inspect an SD image: MBR partitions, sizes, filesystem types.
pub fn inspect(path: &str) -> Result<String, String> {
    let file = std::fs::read(Path::new(path)).map_err(|e| format!("read {path}: {e}"))?;
    let entries = read_mbr(&file)?;

    let mut out = String::new();
    writeln!(out, "image: {path}").unwrap();
    writeln!(
        out,
        "size:  {} bytes ({:.1} MiB)",
        file.len(),
        file.len() as f64 / 1048576.0
    )
    .unwrap();
    writeln!(out, "partitions (MBR):").unwrap();
    for (i, e) in entries.iter().enumerate() {
        let start = e.start_sector as u64 * SECTOR;
        let bytes = e.sector_count as u64 * SECTOR;
        let fs = fs_type(&file, start);
        writeln!(
            out,
            "  p{i}: {} bootable={} start={} ({}) fs={fs}",
            type_name(e.partition_type),
            e.bootable,
            e.start_sector,
            human(bytes)
        )
        .unwrap();
    }
    Ok(out)
}

/// Write a SHA-256 manifest next to the image (image.sha256).
pub fn write_checksum(path: &str) -> Result<String, String> {
    let file = std::fs::read(Path::new(path)).map_err(|e| format!("read {path}: {e}"))?;
    let digest = sha256(&file);
    let manifest = format!("{digest}  {path}\n");
    let manifest_path = format!("{path}.sha256");
    std::fs::write(&manifest_path, &manifest).map_err(|e| format!("write {manifest_path}: {e}"))?;
    Ok(format!("{manifest}-> {manifest_path}"))
}

pub fn sha256(data: &[u8]) -> String {
    // Minimal SHA-256 (FIPS 180-4), no external deps.
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (msg.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|v| format!("{v:08x}")).collect::<String>()
}

fn human(bytes: u64) -> String {
    if bytes >= 1048576 {
        format!("{:.1} MiB", bytes as f64 / 1048576.0)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") == e3b0c442...
        assert_eq!(
            sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn mbr_detection_rejects_trivial() {
        let empty = vec![0u8; 1024];
        assert!(read_mbr(&empty).is_err());
    }
}
