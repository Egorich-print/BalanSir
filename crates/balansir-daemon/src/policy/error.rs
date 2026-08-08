//! Typed errors for the policy domain.
//!
//! Replaces ad-hoc `Result<_, String>` in the policy engine and its TOML
//! loading/validation path with a structured error type that can be matched on
//! and surfaced (logs, metrics, API).

use thiserror::Error;

/// Errors produced while loading, validating or translating policy rules.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum PolicyError {
    #[error("failed to read policy file {path}: {reason}")]
    Io { path: String, reason: String },

    #[error("failed to parse policy file {path}: {reason}")]
    Parse { path: String, reason: String },

    #[error("matcher recursion depth {depth} exceeds maximum {max}")]
    MatcherTooDeep { depth: usize, max: usize },

    #[error("invalid CIDR `{cidr}`: {reason}")]
    InvalidCidr { cidr: String, reason: String },

    #[error("unknown action `{0}` in policy rule")]
    UnknownAction(String),

    #[error("unknown driver `{0}` in policy rule")]
    UnknownDriver(String),

    #[error("policy validation failed for {field}: {reason}")]
    Validation { field: String, reason: String },
}

/// Convenience alias for policy-related results.
pub type PolicyResult<T> = Result<T, PolicyError>;
