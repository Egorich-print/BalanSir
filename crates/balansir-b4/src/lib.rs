//! BalanSir B4 — Rust-native DPI-bypass engine.
//!
//! Intercepts TCP packets via kernel NFQUEUE (pure-Rust netlink, no C
//! dependency), identifies the destination host from TLS SNI, and applies
//! per-domain bypass strategies (MSS rewrite, TCP-option stripping, TTL
//! disorientation, fragmentation, QUIC faking) before returning a verdict.
//!
//! Mission §6 strategy sets (the classic b4 format with tcp/udp/fragmentation/
//! faking planes) live in [`set`], target categories resolve through
//! [`geosite`], and the engine applies the sets' packet mutations.

pub mod config;
#[cfg(target_os = "linux")]
pub mod engine;
pub mod geosite;
pub mod nfq;
#[cfg(target_os = "linux")]
pub mod nfqueue;
pub mod packet;
pub mod reassembly;
pub mod set;
pub mod set_apply;
pub mod strategies;

pub use config::B4Config;
#[cfg(target_os = "linux")]
pub use engine::{B4Engine, B4Stats};
pub use geosite::GeositeStore;
