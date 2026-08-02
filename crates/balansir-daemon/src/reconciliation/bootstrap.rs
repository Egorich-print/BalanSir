use tracing::{error, info, warn};

use crate::reconciliation::{ExecutorAdapter, Reconciler, ReconcilerConfig};
use balansir_common::state::StateStore;
use balansir_common::DesiredState;

/// Bootstrap the system from persisted state
pub async fn bootstrap(
    state_store: &impl StateStore,
    executor: std::sync::Arc<dyn ExecutorAdapter>,
) -> Result<Reconciler, String> {
    info!("Bootstrapping system from persisted state...");

    // 1. Load desired state
    let desired = load_desired_state(state_store).await?;
    info!(
        rule_count = desired.rules.len(),
        driver_count = desired.drivers.len(),
        "Loaded desired state"
    );

    // 2. Create reconciler
    let config = ReconcilerConfig {
        check_interval_secs: 30,
        max_retries: 3,
        retry_delay_secs: 5,
        watchdog_timeout_secs: 30,
        atomic_rollback: true,
    };

    let reconciler = Reconciler::new(desired, executor, config);

    // 3. Run initial reconciliation (apply state)
    if let Err(e) = reconciler.reconcile().await {
        warn!("Initial reconciliation had errors: {}", e);
        // Continue anyway — reconciliation loop will retry
    }

    info!("Bootstrap complete");
    Ok(reconciler)
}

/// Load desired state from state store
async fn load_desired_state(state_store: &impl StateStore) -> Result<DesiredState, String> {
    match state_store.load("desired_state").await {
        Ok(Some(data)) => {
            let state: DesiredState = postcard::from_bytes(&data)
                .map_err(|e| format!("Failed to deserialize desired state: {}", e))?;
            Ok(state)
        }
        Ok(None) => {
            info!("No persisted state found, starting with empty state");
            Ok(DesiredState::default())
        }
        Err(e) => {
            warn!("Failed to load state: {}, starting with empty state", e);
            Ok(DesiredState::default())
        }
    }
}

/// Shutdown hook — save state before exiting
pub async fn save_state_on_exit(reconciler: &Reconciler, state_store: &impl StateStore) {
    info!("Saving state before exit...");

    if let Err(e) = reconciler.save_to_store(state_store).await {
        error!("Failed to save state: {}", e);
    } else {
        info!("State saved successfully");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balansir_common::state::{FileStateStore, StateStoreConfig};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_bootstrap_empty() {
        let dir = tempdir().unwrap();
        let config = StateStoreConfig {
            base_path: dir.path().to_path_buf(),
            ..Default::default()
        };
        let store = FileStateStore::new(&config).await.unwrap();
        let executor = std::sync::Arc::new(crate::reconciliation::DummyExecutorAdapter::new());

        let reconciler = bootstrap(&store, executor).await.unwrap();
        let desired = reconciler.get_desired().await;
        assert!(desired.rules.is_empty());
    }

    #[tokio::test]
    async fn test_save_and_load() {
        let dir = tempdir().unwrap();
        let config = StateStoreConfig {
            base_path: dir.path().to_path_buf(),
            ..Default::default()
        };
        let store = FileStateStore::new(&config).await.unwrap();
        let executor = std::sync::Arc::new(crate::reconciliation::DummyExecutorAdapter::new());

        // Create and save state
        let mut reconciler = Reconciler::new(
            DesiredState::default(),
            executor.clone(),
            ReconcilerConfig::default(),
        );

        reconciler.add_rule(balansir_common::DesiredRule {
            id: 1,
            action: balansir_common::Action::Block,
            priority: 100,
        }).await;

        reconciler.save_to_store(&store).await.unwrap();

        // Reload
        let executor2 = std::sync::Arc::new(crate::reconciliation::DummyExecutorAdapter::new());
        let reconciler2 = bootstrap(&store, executor2).await.unwrap();
        let desired = reconciler2.get_desired().await;
        assert_eq!(desired.rules.len(), 1);
        assert_eq!(desired.rules[0].id, 1);
    }
}
