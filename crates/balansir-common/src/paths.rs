//! Resolve external binaries to absolute paths.
//!
//! Privileged operations must never pick executables from an attacker- or
//! user-controlled `$PATH`. We first look in the standard system dirs, and
//! only fall back to `which`/`$PATH` for user-installed drivers.

use std::path::{Path, PathBuf};

const STANDARD_DIRS: &[&str] = &[
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// Resolve `name` to an absolute path, preferring standard system locations
/// before searching `$PATH`.
pub fn resolve_bin(name: &str) -> Option<PathBuf> {
    for dir in STANDARD_DIRS {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    which::which(name).ok()
}

/// Program name with an absolute path when resolvable (falls back to `name`).
pub fn resolve_bin_or_default(name: &str) -> PathBuf {
    resolve_bin(name).unwrap_or_else(|| PathBuf::from(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolves_standard_location() {
        let path = resolve_bin("sh").expect("sh should resolve");
        assert!(path.is_absolute());
        assert!(path.ends_with("sh"));
    }
}
