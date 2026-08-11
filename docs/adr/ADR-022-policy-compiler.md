# ADR-022: Policy compiler layer (P5)

## Status
Accepted (P5, policy maturity)

## Context

The A3 work (ADR-018) added flow criteria to `DesiredRule` and compiled them
through `apply_rule` into `ActionRequest` and then into `NftRuleSpec`. The
separation principle the roadmap names ("policy must not know how nftables
works, and vice versa") was *behaviorally* true — the executor owned the
nft-specific mapping — but the daemon-side hop
(`DesiredRule → ActionRequest`) was inlined inside `apply_rule`, so it was
not a testable unit and the representation boundary was implicit.

## Decision

Extract an explicit **policy compiler** layer in the daemon:
`policy::compiler::PolicyCompiler`. It is a pure function
`DesiredRule → ActionRequest` with no I/O:

- absent `src_ip`/`dst_ip` compile to the unspecified address (no matcher);
- absent ports compile to `0` (no matcher);
- absent protocol compiles to `0` (any);
- `trace.policy_id` carries the rule id for M3.7 tagging/removal.

`DaemonExecutorAdapter::apply_rule` now calls
`PolicyCompiler::compile(rule)` instead of building the request inline.

The representation chain is now explicit:

```text
DesiredRule   semantic policy (id, action, flow criteria, domain)
   │  PolicyCompiler::compile         (daemon, this ADR)
   ▼
ActionRequest backend-neutral wire request (IpAddr, ports, protocol)
   │  executor: to_nft_spec / to_mark_spec
   ▼
NftRuleSpec   mechanism representation (nft matchers, family-aware)
```

## Consequences

- The policy→wire mapping is a single, unit-testable unit. Policy code (the
  planner and the config compiler) never sees nft; the executor never sees a
  domain or a semantic flow field.
- Behavior is unchanged (the extracted code is byte-identical logic; the
  existing reconcile/integration tests cover it).
- A future backend (routing, DNS sets, B4 drivers) gains a clean seam: it
  consumes `ActionRequest` (or a compiled form) without the executor touching
  policy.
- The executor's `to_nft_spec`/`to_mark_spec` remain the only nft-specific
  code, unchanged by this ADR.

## Verification

- `no_flow_compiles_to_no_matcher`: absent criteria → unspecified/0 fields.
- `flow_criteria_compile_to_concrete_fields`: full v4 flow → concrete fields,
  policy_id carried.
- `partial_flow_leaves_absent_fields_as_no_matcher`: present fields are
  matchers, absent ones are independently "no matcher".
- Existing `apply_rule`/reconcile tests pass unchanged.
- Workspace 18 suites, clippy 0, fmt clean; x86_64 + aarch64 Linux check pass.

## Relation to other gates

- Formalizes the boundary A3 established (ADR-018) and the P4.6 principle.
- Unblocks P6 (DNS policy plane: sets) and P7 (B4 drivers): they extend the
  compiler/executor seam instead of widening the inline `apply_rule`.
