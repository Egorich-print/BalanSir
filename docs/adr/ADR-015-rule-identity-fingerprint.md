# ADR-015: Rule Identity and Idempotency (semantic fingerprint)

## Status
Accepted (Architecture Gate A1)

## Context

BalanSir's reconciliation identifies rules by their `DesiredRule.id`
(`types.rs:402-407`). The daemon passes that id to the executor as
`ActionRequest.trace.policy_id`, the executor tags the installed nft rule with
`balansir:<policy_id>` and uses that comment to remove it by handle
(`service.rs`, `nftables.rs`).

This assumes **same id ⇒ same rule**. That is false: the same id can carry a
different action (or, later, different flow criteria). The audit and Gate A1
identified the resulting defect:

- If rule `id=42` changes `Block → Allow`, the daemon emits `UpdatePolicy(42)`.
  The executor tags both generations `balansir:42`; without a semantic
  identity it would install a second kernel rule under the same comment, and
  `remove_rule_by_comment("balansir:42")` would only delete the first — leaving
  a stale rule.
- Idempotency is unreliable: re-arriving the same id+content cannot be
  distinguished from a changed rule.

The fix must keep the daemon as the sole control-plane authority: the executor
derives identity from what the daemon sends; it does not become a source of
truth.

## Decision

Introduce a **semantic rule fingerprint**: a stable FNV-1a hash over the
postcard encoding of the full `ActionRequest` (`service.rs::rule_fingerprint`).
The executor tracks `policy_id → fingerprint` in its `installed` map.

`NftablesExecutor::execute` now:

1. Computes `fingerprint = rule_fingerprint(request)`.
2. If the installed fingerprint for this `policy_id` already matches →
   `AlreadyApplied` (no kernel change; daemon treats this as success without
   mutating ActualState — `adapters.rs`).
3. Otherwise, if a prior rule exists for this `policy_id`, **remove it first**
   (by comment, idempotent), then install the new rule and remember the new
   fingerprint.

This gives:

```
same id + same content  → AlreadyApplied  (no-op)
same id + new content   → replace         (old rule removed, new installed)
```

`RemoveRule`/`flush` keep clearing the map as before. The nft comment stays
`balansir:<policy_id>` (stable removal identity); the fingerprint is only the
idempotency/replacement discriminator.

The fingerprint is **derived from the operation content** (action + flow
fields), so it automatically covers future flow criteria (A3) without a
separate identity contract. It is not exposed in the plan contract
(`DesiredRule`/`ReconciliationOperation` unchanged) and does not change the
IPC wire shape.

## Consequences

- "same id ≠ same rule" is resolved: action changes under a constant id now
  correctly replace the kernel rule instead of stacking duplicates.
- Idempotent reconcile of an unchanged rule is a true `AlreadyApplied` no-op.
- The daemon remains the sole authority: it sends the full operation; the
  executor derives identity from it. No executor-side desired-state, no second
  planner.
- The fingerprint is stable for identical input (deterministic), so a repeated
  `AddRule` after an executor restart produces the same hash — enabling the A2
  inventory/reconcile path later.
- `HashMap` iteration is not used for decision ordering; the map is only a
  lookup keyed by `policy_id`.

## Verification

- `rule_fingerprint_is_stable_and_semantic`: same content → same hash; same id
  + different action → different hash.
- Executor suite green (22 tests). Workspace 18 suites, clippy 0, fmt clean,
  x86_64 + aarch64 Linux check pass.
- (Privileged, env-gated) the netns backend test still drives the production
  backend; replacement is exercised when run as root.

## Relation to other gates

- Complements **A2** (orphan reconciliation): a deterministic fingerprint is
  the identity an executor inventory report can carry.
- Does **not** solve the ack-gap orphan by itself (that is A2's reconcile
  decision).
