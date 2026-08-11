//! Per-path MTU state (P7.2, ADR-026).
//!
//! The executor owns the *applied* path-MTU state and reports it to the daemon
//! (like the rule inventory). MTU is deliberately **per-path**, never a global
//! interface setting (ADR-024 §6). A `PathMtuApplier` is the privileged hook
//! that actually changes the host (e.g. route-level MTU / MSS); the store
//! keeps the authoritative applied set so the daemon can reconcile.

use balansir_common::PathMtu;
use std::collections::HashMap;

/// Privileged hook that applies/removes a per-path MTU on the host.
///
/// The store records state; the applier is what touches the kernel. In tests
/// and on non-privileged builds this is a no-op record-only applier; the real
/// Linux implementation would set route-level MTU/MSS for the path.
#[async_trait::async_trait]
pub trait PathMtuApplier: Send + Sync {
    /// Apply a per-path MTU.
    async fn apply(&self, path: &str, mtu: u16) -> Result<(), String>;
    /// Remove a per-path MTU (restore default).
    async fn restore(&self, path: &str) -> Result<(), String>;
}

/// Record-only applier: tracks intent but performs no host change. Used when
/// no privileged mechanism is wired, so the executor honestly reports the
/// requested state without pretending a kernel change happened.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecordOnlyApplier;

#[async_trait::async_trait]
impl PathMtuApplier for RecordOnlyApplier {
    async fn apply(&self, _path: &str, _mtu: u16) -> Result<(), String> {
        Ok(())
    }
    async fn restore(&self, _path: &str) -> Result<(), String> {
        Ok(())
    }
}

/// The executor's applied per-path MTU state, keyed by path.
pub struct PathMtuStore {
    applied: std::sync::Mutex<HashMap<String, u16>>,
    applier: Box<dyn PathMtuApplier>,
}

impl PathMtuStore {
    pub fn new(applier: Box<dyn PathMtuApplier>) -> Self {
        Self {
            applied: std::sync::Mutex::new(HashMap::new()),
            applier,
        }
    }

    /// Apply (or update) a per-path MTU. On applier failure the in-memory state
    /// is left unchanged so the daemon can retry — no partial accounting.
    pub async fn set(&self, path: &str, mtu: u16) -> Result<(), String> {
        self.applier.apply(path, mtu).await?;
        self.applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(path.to_string(), mtu);
        Ok(())
    }

    /// Remove a per-path MTU (rollback). Returns Ok whether or not it was set.
    pub async fn restore(&self, path: &str) -> Result<(), String> {
        self.applier.restore(path).await?;
        self.applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(path);
        Ok(())
    }

    /// The currently applied path-MTU set (non-authority, for reconciliation).
    pub fn state(&self) -> Vec<PathMtu> {
        self.applied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(path, mtu)| PathMtu {
                path: path.clone(),
                mtu: *mtu,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_restore_state_roundtrip() {
        let store = PathMtuStore::new(Box::new(RecordOnlyApplier));
        assert!(store.state().is_empty());

        store.set("example.com", 1400).await.unwrap();
        assert_eq!(
            store.state(),
            vec![PathMtu {
                path: "example.com".into(),
                mtu: 1400
            }]
        );

        // Update same path.
        store.set("example.com", 1380).await.unwrap();
        assert_eq!(store.state().len(), 1);
        assert_eq!(store.state()[0].mtu, 1380);

        // Restore removes it.
        store.restore("example.com").await.unwrap();
        assert!(store.state().is_empty());
    }

    #[tokio::test]
    async fn failed_applier_does_not_record() {
        struct Failing;
        #[async_trait::async_trait]
        impl PathMtuApplier for Failing {
            async fn apply(&self, _p: &str, _m: u16) -> Result<(), String> {
                Err("denied".into())
            }
            async fn restore(&self, _p: &str) -> Result<(), String> {
                Ok(())
            }
        }
        let store = PathMtuStore::new(Box::new(Failing));
        assert!(store.set("x.com", 1300).await.is_err());
        assert!(store.state().is_empty());
    }
}
