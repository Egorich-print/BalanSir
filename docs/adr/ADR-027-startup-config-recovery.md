# ADR-027: Startup configuration recovery (P7.2.1)

## Status
Accepted (P7.2.1)

## Context

Operational invariant: **BalanSir must restore the last accepted DesiredState
after a reboot by itself.** Before this ADR, the daemon started with
`DesiredState::default()` and only learned policy when an operator ran
`balansir-cli reload <file>`. On a router/embedded device that means: reboot →
empty desired → no enforcement → human must intervene. Unacceptable.

The owner's P7.2.1 scope: `BALANSIR_CONFIG` as the startup source, load +
validate **before the first reconcile**, never substitute empty for a broken
config, keep STRICT semantics, no new config authority, CLI `reload` stays the
runtime mechanism, and the fingerprint must reflect the accepted config.

## Decision

Add a startup config loader (`daemon::startup`):

- `BALANSIR_CONFIG` points at the same strict TOML the CLI `reload` accepts.
- `load_startup_desired` returns:
  - `Empty` when the env var is unset (dev/first-boot; daemon starts empty,
    matching today's default);
  - `Loaded(DesiredState)` when the config compiles strictly (ADR-010);
  - `Err` when the var is set but the file is missing **or** the config is
    malformed — a **fatal startup error**, never silently replaced by an empty
    state (that would silently disable enforcement).
- `main.rs` loads this **before `Reconciler::new`**, passes the loaded state as
  the initial desired, then calls `set_desired` to record the raw state + its
  fingerprint (P4.8/ADR-021), so `balansir-cli fingerprint` reflects exactly
  what was accepted at boot.
- No new authority: the compile path is the same `DesiredConfig → DesiredState`
  the CLI uses; `reload` remains the runtime mechanism.
- systemd unit gains `Environment=BALANSIR_CONFIG=/etc/balansir/balansir.toml`;
  `config/balansir.toml` is the reference example.

## Consequences

- A reboot restores the last accepted desired state automatically: config →
  DesiredState → first reconcile, before the executor inventory is even
  consulted (A2 seed still runs; the planner then converges against the loaded
  desired).
- A broken startup config cannot silently disable enforcement: the daemon
  fails loudly at boot (STRICT semantics preserved).
- Fingerprint correctness: the startup path records raw + fingerprint exactly
  like a runtime `reload`, so operator verification is consistent across boot
  and live reload.
- Development/first-boot is unchanged: no `BALANSIR_CONFIG` → empty start.
- Explicitly **no** persistent config database/state store: `BALANSIR_CONFIG` +
  the file source is the minimal fix (owner's instruction).

## Verification

- `valid_config_compiles_to_desired`: a config with a rule compiles to a
  non-empty `DesiredState` (startup config ≠ empty desired).
- `malformed_config_is_fatal_not_empty` / `missing_file_is_fatal_not_empty`:
  a broken or pointed-at-but-missing config is `Err`, never `Empty`.
- `no_env_starts_empty`: unset env → `Empty`.
- `non_unicode_env_is_rejected`.
- Fingerprint-after-`set_desired` is covered by the P4.8 test
  (`config_fingerprint_tracks_last_accepted_reload`); the startup path uses the
  same `set_desired`.
- Workspace 18 suites, clippy 0, fmt clean; x86_64 + aarch64 Linux check pass.

## Relation to other gates

- Composes with the ownership loop (ADR-020): startup desired is the seed the
  ownership loop converges to.
- Composes with the config fingerprint (ADR-021): boot-time fingerprint is
  recorded identically to reload-time.
- **Not** merged with the DNS-registry single-truth fix (owner's instruction):
  that is a separate, architecturally-significant milestone before P7.3.
