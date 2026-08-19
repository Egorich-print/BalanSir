//! Policy compilation (P5): semantic `DesiredRule` → backend-neutral
//! `ActionRequest`. The live mechanism mapping lives in the executor; this
//! module is the single place that maps policy semantics onto the wire
//! contract (ADR P4.6). The legacy in-process packet matcher/engine was
//! removed — packet decisions are made by the kernel via nftables.

pub mod compiler;
pub mod error;

pub use compiler::*;
pub use error::*;
