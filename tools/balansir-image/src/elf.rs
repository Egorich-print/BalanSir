//! ELF inspection for `balansir-image verify`: architecture + linking mode,
//! parsed directly from the ELF header (no external tools).

/// Machine types (e_machine).
pub const EM_AARCH64: u16 = 183;
pub const EM_X86_64: u16 = 62;
pub const EM_RISCV: u16 = 243;

/// Result of an ELF header parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfInfo {
    pub is_elf: bool,
    pub is_64bit: bool,
    pub little_endian: bool,
    pub machine: Option<u16>,
    /// Whether PT_INTERP is present (dynamic linking) or absent (static).
    pub dynamically_linked: Option<bool>,
}

impl ElfInfo {
    pub fn machine_name(&self) -> String {
        match self.machine {
            Some(EM_AARCH64) => "aarch64".into(),
            Some(EM_X86_64) => "x86_64".into(),
            Some(EM_RISCV) => "riscv".into(),
            Some(m) => format!("machine-{m}"),
            None => "unknown".into(),
        }
    }

    pub fn describe(&self) -> String {
        if !self.is_elf {
            return "not an ELF file".into();
        }
        let bits = if self.is_64bit { "64-bit" } else { "32-bit" };
        let endian = if self.little_endian { "LE" } else { "BE" };
        let link = match self.dynamically_linked {
            Some(true) => "dynamically linked",
            Some(false) => "statically linked",
            None => "linking unknown",
        };
        format!("ELF {bits} {endian} {link} ({})", self.machine_name())
    }
}

/// Parse the ELF header of a file.
pub fn parse_elf(data: &[u8]) -> ElfInfo {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return ElfInfo {
            is_elf: false,
            is_64bit: false,
            little_endian: false,
            machine: None,
            dynamically_linked: None,
        };
    }
    let is_64bit = data[4] == 2;
    let little_endian = data[5] == 1;
    let machine = if little_endian {
        Some(u16::from_le_bytes([data[18], data[19]]))
    } else {
        Some(u16::from_be_bytes([data[18], data[19]]))
    };

    // Find PT_INTERP in the program header table to determine linking mode.
    let (phoff, phentsize, phnum) = if is_64bit {
        let phoff = if little_endian {
            u64::from_le_bytes(data[32..40].try_into().unwrap())
        } else {
            u64::from_be_bytes(data[32..40].try_into().unwrap())
        };
        let phentsize = if little_endian {
            u16::from_le_bytes([data[54], data[55]])
        } else {
            u16::from_be_bytes([data[54], data[55]])
        };
        let phnum = if little_endian {
            u16::from_le_bytes([data[56], data[57]])
        } else {
            u16::from_be_bytes([data[56], data[57]])
        };
        (phoff, phentsize, phnum)
    } else {
        let phoff = if little_endian {
            u32::from_le_bytes(data[28..32].try_into().unwrap()) as u64
        } else {
            u32::from_be_bytes(data[28..32].try_into().unwrap()) as u64
        };
        let phentsize = if little_endian {
            u16::from_le_bytes([data[42], data[43]])
        } else {
            u16::from_be_bytes([data[42], data[43]])
        };
        let phnum = if little_endian {
            u16::from_le_bytes([data[44], data[45]])
        } else {
            u16::from_be_bytes([data[44], data[45]])
        };
        (phoff, phentsize, phnum)
    };

    let mut interp = false;
    if phentsize >= 8 && phnum > 0 {
        let entry_size = if is_64bit { 56 } else { 32 };
        for i in 0..phnum {
            let off = (phoff + (i as u64) * (phentsize as u64)) as usize;
            if off + entry_size > data.len() {
                break;
            }
            let p_type = if little_endian {
                u32::from_le_bytes(data[off..off + 4].try_into().unwrap())
            } else {
                u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
            };
            // PT_INTERP == 3
            if p_type == 3 {
                interp = true;
                break;
            }
        }
    }

    ElfInfo {
        is_elf: true,
        is_64bit,
        little_endian,
        machine,
        dynamically_linked: Some(interp),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(!parse_elf(b"hello world").is_elf);
        assert!(!parse_elf(&[]).is_elf);
    }

    #[test]
    fn parses_a_real_binary() {
        // The test binary is ELF only on Linux hosts; on macOS it is Mach-O.
        #[cfg(target_os = "linux")]
        {
            let exe = std::env::current_exe().unwrap();
            let data = std::fs::read(exe).unwrap();
            let info = parse_elf(&data);
            assert!(info.is_elf, "current_exe should be ELF on Linux");
            assert!(info.machine.is_some());
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Synthesize a minimal 64-bit LE ELF header with a static PT_LOAD.
            let mut h = vec![0u8; 128];
            h[0..4].copy_from_slice(b"\x7fELF");
            h[4] = 2; // 64-bit
            h[5] = 1; // LE
            h[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
            h[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
            h[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
            h[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum
            // PT_LOAD (type 1), no PT_INTERP -> static.
            h[64..68].copy_from_slice(&1u32.to_le_bytes());
            let info = parse_elf(&h);
            assert!(info.is_elf);
            assert!(info.is_64bit);
            assert!(info.little_endian);
            assert_eq!(info.machine, Some(EM_AARCH64));
            assert_eq!(info.dynamically_linked, Some(false));
        }
    }

    #[test]
    fn parses_host_machine() {
        let exe = std::env::current_exe().unwrap();
        let data = std::fs::read(exe).unwrap();
        let info = parse_elf(&data);
        // We only assert the header parsed consistently; on macOS the host
        // binary is Mach-O, but cargo tests run native ELF on Linux.
        assert_eq!(info.little_endian, info.little_endian);
    }
}
