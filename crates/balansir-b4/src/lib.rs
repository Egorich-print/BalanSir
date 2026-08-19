//! BalanSir B4 — Rust-native DPI-bypass engine.
//!
//! Intercepts TCP packets via kernel NFQUEUE (pure-Rust netlink, no C
//! dependency), identifies the destination host from TLS SNI, and applies
//! per-domain bypass strategies (MSS rewrite, TCP-option stripping, TTL
//! disorientation) before returning a verdict.

pub mod config;
#[cfg(target_os = "linux")]
pub mod engine;
pub mod nfq;
#[cfg(target_os = "linux")]
pub mod nfqueue;
pub mod packet;
pub mod reassembly;
pub mod strategies;

pub use config::B4Config;
#[cfg(target_os = "linux")]
pub use engine::{B4Engine, B4Stats};
