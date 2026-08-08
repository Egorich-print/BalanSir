# ADR-009: Typed Error Model Across Policy, Profile and Reconciliation

## Status

Accepted

## Context

Error propagation in the policy and reconciliation layers relied on ad-hoc
`Result<_, String>` and bare `Box<dyn Error>` from `thiserror`. This had three
costs:

1. **No structured discrimination.** Callers (API handlers, coordinator,
   bootstrap) had to string-match to decide whether a failure was a config
   parse error, an IO error, or a reconciliation/apply failure, making retry
   and downgrade logic brittle.
2. **No audit trail.** Log lines carried free-form messages; there was no
   stable error taxonomy to correlate across reconcile attempts.
3. **Leaky boundaries.** `PolicyFile::load` returned `anyhow`-style strings
   while `bootstrap` produced its own ad-hoc failure types, so a single
   reconcile failure surfaced as unrelated variants at different layers.

## Decision

Introduce three `thiserror`-derived error enums at the layer that owns the
failure domain, each with a `Result<T>` alias:

- `PolicyError` (`balansir-daemon/src/policy/error.rs`) — policy loading,
  CIDR/TOML parsing, matcher validation (`MatcherTooDeep`, `InvalidCidr`,
  `UnknownAction`, `UnknownDriver`, `Validation`, plus `Io`/`Parse`).
- `ProfileError` (`balansir-common/src/profile.rs`) — profile load and field
  validation (`Io`, `Parse`, `Validation`).
- `ReconciliationError` (`balansir-daemon/src/reconciliation/error.rs`) — the
  reconcile pipeline: `Config`, `StateLoad`, `StateSave`, `Deserialize`,
  `Serialize`, `Reconcile`, `ApplyRule`.

Rules of use:

1. A layer returns only the error type it owns; it maps foreign failures into
   its own variant at the boundary (`map_err`).
2. `#[from]` is used sparingly — only where the source type maps uniquely to
   one variant — to avoid ambiguous conversions (this is why the inner
   field is named `reason`, not `source`).
3. `PolicyRuleToml::to_rule` returns `PolicyResult` so a single malformed rule
   fails loudly during load rather than being dropped silently.
4. Errors remain logged as tracing events; no error variant is printed to the
   API response body.

## Consequences

**Positive.** Reconcile call sites can now branch on variant (e.g. retry
`ApplyRule`, surface `Config` upstream). A stable taxonomy feeds clippy/lints
and future metrics. Nullability of "rule loading succeeded" vs "reconcile
failed" is no longer conflated.

**Trade-off.** Each layer must map errors at its boundary; refactors touching
`PolicyFile::load` now require updating its variant mapping. Some `reason`
strings duplicate the original error text (kept for operators).

## Alternatives considered

- Keep `Result<_, String>` everywhere: smallest diff, but classification at
  call sites (the API layer, ADR-007 reconcile path) is the actual payoff, so
  rejected.
- Single global error enum in `balansir-common`: couples leaf crates to one
  blob, violates hexagonal layering (common must not know the daemon's
  reconciliation lifecycle), rejected.

## Related

- ADR-007 (revert-plan rollback) — relies on `ReconcileKind` variants for
  per-failure branch logic on the executor side.