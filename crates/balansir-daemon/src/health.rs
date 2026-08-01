use std::sync::Mutex;
use std::time::{Duration, Instant};

use balansir_common::CircuitState;

/// Circuit breaker for health monitoring
pub struct CircuitBreaker {
    inner: Mutex<CircuitBreakerInner>,
    config: CircuitBreakerConfig,
}

struct CircuitBreakerInner {
    state: CircuitState,
    failure_count: u32,
    last_failure: Option<Instant>,
    last_success: Option<Instant>,
}

/// Configuration for circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub recovery_timeout: Duration,
    pub max_retries: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            recovery_timeout: Duration::from_secs(30),
            max_retries: 2,
        }
    }
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            inner: Mutex::new(CircuitBreakerInner {
                state: CircuitState::Closed,
                failure_count: 0,
                last_failure: None,
                last_success: None,
            }),
            config,
        }
    }

    /// Get current circuit state
    pub fn state(&self) -> CircuitState {
        self.inner
            .lock()
            .map(|inner| inner.state)
            .unwrap_or(CircuitState::Open)
    }

    /// Record a successful operation
    pub fn record_success(&self) {
        let Ok(mut inner) = self.inner.lock() else {
            tracing::error!("Failed to acquire circuit breaker lock");
            return;
        };

        inner.failure_count = 0;
        inner.last_success = Some(Instant::now());

        if inner.state == CircuitState::HalfOpen {
            inner.state = CircuitState::Closed;
            tracing::info!("Circuit breaker closed (recovered)");
        }
    }

    /// Record a failed operation
    pub fn record_failure(&self) {
        let Ok(mut inner) = self.inner.lock() else {
            tracing::error!("Failed to acquire circuit breaker lock");
            return;
        };

        inner.failure_count += 1;
        inner.last_failure = Some(Instant::now());

        if inner.failure_count >= self.config.failure_threshold {
            if inner.state != CircuitState::Open {
                tracing::warn!(
                    failures = inner.failure_count,
                    "Circuit breaker opened"
                );
            }
            inner.state = CircuitState::Open;
        }
    }

    /// Check if a request should be allowed
    pub fn allow_request(&self) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };

        match inner.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(last_failure) = inner.last_failure {
                    if last_failure.elapsed() >= self.config.recovery_timeout {
                        inner.state = CircuitState::HalfOpen;
                        tracing::info!("Circuit breaker half-open (probing)");
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Reset circuit breaker to closed state
    pub fn reset(&self) {
        let Ok(mut inner) = self.inner.lock() else {
            tracing::error!("Failed to acquire circuit breaker lock");
            return;
        };

        inner.state = CircuitState::Closed;
        inner.failure_count = 0;
        inner.last_failure = None;
        tracing::info!("Circuit breaker reset");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_basic() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());

        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_circuit_breaker_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(0),
            max_retries: 2,
        };
        let cb = CircuitBreaker::new(config);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // After recovery timeout, should be half-open
        assert!(cb.allow_request());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());

        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }
}
