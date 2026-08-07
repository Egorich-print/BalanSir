//! In-memory executor adapter used for testing and offline bootstrap.

use crate::reconciliation::reconciler::ExecutorAdapter;
use balansir_common::{ActionRequest, ActionResult};
use std::sync::atomic::{AtomicU32, Ordering};

/// Dummy executor for testing.
pub struct DummyExecutorAdapter {
    count: AtomicU32,
}

impl DummyExecutorAdapter {
    pub fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
        }
    }
}

impl Default for DummyExecutorAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ExecutorAdapter for DummyExecutorAdapter {
    async fn execute(&self, _request: &ActionRequest) -> ActionResult {
        let id = self.count.fetch_add(1, Ordering::Relaxed);
        ActionResult::Applied {
            execution_time_us: 100,
            rule_id: Some(id + 1),
        }
    }

    async fn rule_count(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }

    async fn remove_rule(&self, _rule_id: u32) -> ActionResult {
        self.count.fetch_sub(1, Ordering::Relaxed);
        ActionResult::Applied {
            execution_time_us: 50,
            rule_id: Some(_rule_id),
        }
    }
}
