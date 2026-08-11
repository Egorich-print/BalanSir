//! B4 engine (P7.1, ADR-024).
//!
//! B4 is the **policy-controlled connectivity adaptation layer**: it decides
//! *how* to deliver a flow the policy already admitted, under the current
//! network conditions — never *what* should happen (that is the daemon's
//! authority). This module is a pure, testable runtime loop:
//!
//! ```text
//! observe → classify → adapt (MTU / DNS-path) → re-observe → recover / strict-fail
//! ```
//!
//! Constraints honored (ADR-024):
//! - No `Path`/`Session`/`Mechanism`/BTP abstractions; no connection owner.
//! - Policy stays above B4; B4 never becomes an authority.
//! - VPN is not the default; B4 first improves the *direct* path.
//! - Observation is host-stack-only (no MITM); injected via the `B4Observer`
//!   trait so the state machine has no I/O.
//! - STRICT is the default fail semantic.
//!
//! This is a daemon-side adapter; the privileged executor stays dumb.

/// Connectivity classification (direct/degraded/interfered/blocked/unknown).
pub mod classify;
/// TOML configuration loading for B4 policy + engine.
pub mod config;
/// Controller wiring the engine to the executor boundary + ownership (P7.2).
pub mod controller;
/// Real host-stack + DNS observation sources (P7.2).
pub mod host;
/// Host-stack observation signals and the observer trait.
pub mod observe;
/// Policy: which mechanisms a flow may use and how to fail (STRICT default).
pub mod policy;
/// Adaptation decisions (MTU / DNS-path) and the runtime loop state machine.
pub mod state;

pub use classify::{classify, B4Class};
pub use observe::{B4Observation, B4Observer};
pub use policy::{B4FailSemantic, B4Policy, B4Profile};
pub use state::{B4Decision, B4Engine, B4Event, B4State};
