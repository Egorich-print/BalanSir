# ADR-021: Config fingerprint (P4.8)

## Status
Accepted (P4.8, production configuration)

## Context

The P4.8 item ("production configuration") already has: atomic reload
(ADR-010), strict validation (ADR-010), `dry-run`/`explain` (M3.4.3), and
transactional rollback on failed reload. What was missing for an operational
interface was **verifiability**: the operator cannot currently tell what the
daemon has actually loaded. `DesiredState` is delivered over the wire as
postcard; nothing proves that the running daemon matches the config file on
disk.

## Decision

Introduce a **config fingerprint**: a stable FNV-1a hash over the postcard
encoding of the whole accepted `DesiredState` (`common::config_fingerprint`).

- The daemon records the fingerprint of the **last accepted config** on
  `set_desired` and on a *successful* `reload` (ADR-010 transactional: a
  failed reload leaves both the desired state and the fingerprint unchanged).
- A new IPC query, `GetConfigFingerprint`, returns `Option<u64>` (`None` when
  no config has been set yet).
- The CLI exposes it in `status` and as a dedicated `fingerprint` subcommand.

Properties:

- **Stable:** identical desired state → identical fingerprint (any change to
  rules/drivers changes it).
- **Transactional:** the fingerprint is only updated when the reload actually
  commits; a failed reload keeps the old fingerprint.
- **Compile-level:** computed over the compiled state (post-flow-compiler),
  so it reflects exactly what the planner will reconcile against.

This is deliberately a *verification* primitive, not a transport: the CLI can
also compute the fingerprint of a local config file to compare
"what I meant to load" vs "what the daemon has" — the authoritative value is
the daemon's.

## Consequences

- Operators can verify loaded config without trusting a log line.
- A future config-versioning/schema-migration layer (P4.8) can key rollback
  and change-detection off this fingerprint.
- Postcard-encoding dependence is internal; the fingerprint is not stable
  across wire-schema versions (daemon+CLI upgrade together, same as the wire).
- No behavior change for reload itself; the fingerprint is additive.

## Verification

- `identical_state_has_identical_fingerprint` / `different_state_has_different_fingerprint`
  (common): stability and change-detection.
- `config_fingerprint_tracks_last_accepted_reload` (daemon): fingerprint is
  `None` initially, updated on successful reload, changes when the candidate
  changes, and is unchanged after a failed reload on a fresh reconciler.
- Workspace 18 suites, clippy 0, fmt clean; x86_64 + aarch64 Linux check pass.

## Relation to other gates

- Complements the P1 fail-closed flag (ADR-019) and the ownership loop
  (ADR-020): together they make the daemon's *intended* state, its *observed*
  state, and the *loaded config* all verifiable.
- Feeds later P4.8 work (schema migration, config versioning) and P14 WebUI
  (a "config loaded: <fp>" display is a direct use).
