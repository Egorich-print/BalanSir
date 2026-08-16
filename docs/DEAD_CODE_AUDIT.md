# BalanSir Dead Code Audit

**Date**: 2026-08-17
**Method**: Repository-wide grep, `cargo check`, `cargo clippy`, module dependency tracing.

## Legend

| Status | Meaning |
|--------|---------|
| CANONICAL | Used in production, essential |
| DEAD | Never compiled or never called outside dead module |
| TEST-ONLY | Only used in `#[cfg(test)]` or test crates |
| UNWIRED | Implementation exists but never instantiated in production |
| OPTIONAL | Operator utility, not runtime |

---

## Findings

### 1. `crates/balansir-common/src/path_health.rs` — DEAD

**Status**: DEAD

**Evidence**: `crates/balansir-common/src/lib.rs:23` has `pub use balansir_health as path_health;` — this re-export shadows any `path_health.rs` file. There is no `mod path_health;` declaration in `lib.rs`. The file is identical to `crates/balansir-health/src/lib.rs` (555 lines, zero diff). It is never compiled.

**Action**: DELETE file.

---

### 2. `crates/balansir-daemon/src/reconciliation/bootstrap.rs` — DEAD

**Status**: DEAD

**Evidence**: `bootstrap()` function is never called from `main.rs`, `startup.rs`, or any production code path. Only referenced in `error.rs` comments and one test helper (`test_bootstrap_from_empty_store`). The reconciler is created directly in `main.rs` without using this module.

**Action**: Remove module declaration from `mod.rs` and delete file.

---

### 3. `crates/balansir-executor/src/iprule.rs` — UNWIRED

**Status**: UNWIRED

**Evidence**: `IpRuleBackend` struct exists with full implementation (`add_fwmark_rule`, `del_fwmark_rule`, `add_table`, `flush_rules`, tests). Referenced only in a comment in `service.rs:64` ("the `IpRuleBackend` capability... is implemented and unit-tested so fwmark+ip-rule is ready to wire when the daemon contract can express a mark↔table pair"). Never instantiated in production.

**Reason**: The daemon policy engine does not yet emit fwmark+table pairs. When it does, this backend is ready. Keeping it as documented readiness.

**Action**: Keep. Document as UNWIRED but ready.

---

### 4. `RecordOnlyApplier` (path_mtu.rs) — TEST-ONLY

**Status**: TEST-ONLY

**Evidence**: Defined at `crates/balansir-executor/src/path_mtu.rs:29`. Used only in tests at line 190 (`PathMtuStore::new(Box::new(RecordOnlyApplier))`). Production service.rs uses `RouteMtuApplier` (confirmed: `service.rs:87`).

**Action**: Keep. Test fixture.

---

### 5. `RecordOnlyGatewayBackend` (gateway.rs) — TEST-ONLY

**Status**: TEST-ONLY

**Evidence**: `crates/balansir-executor/src/gateway.rs:322`. Used in `ExecutorServices::new()` as default (`service.rs:47`) and in gateway tests (`gateway.rs:381,400`). Production daemon wires `NftablesGatewayBackend`.

**Action**: Keep. Default fallback for test/standalone mode.

---

### 6. `DummyExecutorAdapter` (reconciliation/dummy.rs) — TEST-ONLY

**Status**: TEST-ONLY

**Evidence**: `crates/balansir-daemon/src/reconciliation/dummy.rs`. Used in `reconciler.rs:232` (bootstrap test), `reconciler.rs:622` (test helper). Also re-exported at `mod.rs:15`.

**Action**: Keep. Test fixture.

---

### 7. `tools/balansir-image/` — OPTIONAL

**Status**: OPTIONAL

**Evidence**: Standalone CLI binary for image inspection/checksum/verify. Zero dependencies. Referenced only in `docs/BUILDROOT_IMAGE.md`. No Makefile target, no CI, no runtime dependency.

**Action**: Keep. Operator utility.

---

### 8. `ss_bin()` in dns.rs — CANONICAL

**Status**: CANONICAL

**Evidence**: Used in `health_check()` at `dns.rs:642` — checks if DNS UDP port is listening via `ss -ulnp`.

**Action**: No change.

---

### 9. OTA crate warnings — PRE-EXISTING

**Status**: Pre-existing, not my code

**Evidence**: 16 warnings in `balansir-ota` (unused imports, deprecated `base64::decode`, `daemon_socket` field never read, `DEFAULT_MOUNT` constant never used). These are in files the user marked as not-to-touch or are pre-existing from the OTA implementation.

**Action**: Leave for now. Not dead code — just unused variables/imports in incomplete OTA.

---

## Summary

| Component | Status | Action |
|-----------|--------|--------|
| `common/src/path_health.rs` | DEAD | DELETE |
| `reconciliation/bootstrap.rs` | DEAD | DELETE |
| `iprule.rs` | UNWIRED | Keep, document |
| `RecordOnlyApplier` | TEST-ONLY | Keep |
| `RecordOnlyGatewayBackend` | TEST-ONLY | Keep |
| `DummyExecutorAdapter` | TEST-ONLY | Keep |
| `tools/balansir-image/` | OPTIONAL | Keep |
| `ss_bin()` in dns.rs | CANONICAL | Keep |
| OTA warnings | Pre-existing | Leave |

---

## Duplicate Check

| Area | Finding |
|------|---------|
| DNS | Single canonical `dns.rs` forwarder + `dns_plane.rs` observation. No duplicates. |
| NAT/firewall | Single executor gateway backend. `RecordOnlyGatewayBackend` is test-only. |
| Policy | Single `policy/` module in daemon. |
| nftables | Single `nftables.rs` in executor. |
| path_health | `balansir-health` crate is canonical; `common/src/path_health.rs` is dead duplicate. |
