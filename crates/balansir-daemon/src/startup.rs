//! Startup configuration recovery (P7.2.1, ADR-027).
//!
//! Operational invariant: **after a reboot, BalanSir must restore the last
//! accepted DesiredState by itself** — no operator `reload` required. On a
//! router/embedded device, a daemon that starts empty and stays empty until a
//! human runs `balansir-cli reload` is unacceptable (no enforcement, silent
//! fail-open).
//!
//! Design:
//! - `BALANSIR_CONFIG` points at the startup config file (the same strict
//!   TOML format the CLI `reload` accepts).
//! - Loading + validation happen **before the first reconcile**.
//! - A valid config compiles to `DesiredState` and is reconciled at startup.
//! - A **malformed** config is a fatal startup error: we never substitute an
//!   empty `DesiredState` for a broken config (that would silently disable
//!   enforcement). STRICT semantics preserved.
//! - A **missing** `BALANSIR_CONFIG` is not an error: the daemon starts empty
//!   (development / first-boot behavior), matching today's default.
//! - No new config authority: `DesiredConfig → DesiredState` is the same
//!   strict compile (ADR-010) the CLI uses; the CLI `reload` remains the
//!   runtime mechanism.
//!
//! The daemon records the fingerprint of the accepted config (P4.8/ADR-021),
//! so `balansir-cli fingerprint` reflects exactly what was loaded at boot.

use balansir_common::DesiredState;

/// How to obtain the startup desired state.
pub enum StartupDesired {
    /// No `BALANSIR_CONFIG` set — start empty (dev/first-boot behavior).
    Empty,
    /// A config was loaded and strictly compiled.
    Loaded(DesiredState),
}

/// Load the startup desired state from `BALANSIR_CONFIG`.
///
/// - env var unset → `Ok(StartupDesired::Empty)`.
/// - env var set, file missing → `Err` (fatal; we do not silently start empty
///   when the operator pointed at a config that is not there).
/// - env var set, config malformed → `Err` (fatal; never substitute empty).
/// - valid → `Ok(StartupDesired::Loaded(compiled))`.
pub fn load_startup_desired(
    env: Result<String, std::env::VarError>,
) -> Result<StartupDesired, String> {
    match env {
        Err(std::env::VarError::NotPresent) => Ok(StartupDesired::Empty),
        Err(std::env::VarError::NotUnicode(_)) => Err("BALANSIR_CONFIG is not valid UTF-8".into()),
        Ok(path) => {
            let config = balansir_control::provider::DesiredConfig::from_file(&path)
                .map_err(|e| format!("startup config {path}: {e}"))?;
            let state = balansir_common::DesiredState::try_from(config)
                .map_err(|e| format!("startup config {path}: {e}"))?;
            Ok(StartupDesired::Loaded(state))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::Action;

    #[test]
    fn no_env_starts_empty() {
        assert!(matches!(
            load_startup_desired(Err(std::env::VarError::NotPresent)).unwrap(),
            StartupDesired::Empty
        ));
    }

    #[test]
    fn valid_config_compiles_to_desired() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("balansir.toml");
        std::fs::write(
            &path,
            "[[rules]]\nid = 1\naction = \"block\"\npriority = 100\n",
        )
        .unwrap();
        let loaded = load_startup_desired(Ok(path.display().to_string())).unwrap();
        match loaded {
            StartupDesired::Loaded(state) => {
                assert_eq!(state.rules.len(), 1);
                assert_eq!(state.rules[0].id, 1);
                assert_eq!(state.rules[0].action, Action::Block);
            }
            StartupDesired::Empty => panic!("valid config must not start empty"),
        }
    }

    #[test]
    fn malformed_config_is_fatal_not_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("balansir.toml");
        std::fs::write(&path, "[[rules]]\nid = 1\naction = \"bogus\"\n").unwrap();
        assert!(
            load_startup_desired(Ok(path.display().to_string())).is_err(),
            "malformed config must be a fatal startup error, never empty"
        );
    }

    #[test]
    fn missing_file_is_fatal_not_empty() {
        let path = "/nonexistent/balansir-this-does-not-exist.toml";
        assert!(
            load_startup_desired(Ok(path.to_string())).is_err(),
            "a pointed-at-but-missing config must be fatal"
        );
    }

    #[test]
    fn non_unicode_env_is_rejected() {
        assert!(load_startup_desired(Err(std::env::VarError::NotUnicode(
            std::ffi::OsString::new()
        )))
        .is_err());
    }
}
