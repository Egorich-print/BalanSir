# ADR-019: Empty-config action (fail-open vs fail-closed)

## Status
Accepted (Product Decision P1)

## Context

Gate v1 §12 recorded that an empty desired state installs nothing — honest,
but product-dependent: on a firewall "no rules" usually means "permissive by
accident". The Production Readiness Gate classified fail-open vs fail-closed
as a **product decision** (`PRODUCT_DECISIONS.md`, P1). The owner chose to
make it a compile-time config choice, with fail-open remaining the default to
preserve current behavior.

The constraint from the A-series gates: the executor stays non-authoritative.
A fail-closed default must not be an executor-side "when handed empty, drop
everything" behavior — that would give the mechanism a policy decision the
daemon is supposed to own.

## Decision

Add a top-level config flag, `[policy] empty_config_action`, with two values:

- `"pass"` (default): an empty rule set compiles to an empty desired state —
  the current fail-open behavior, unchanged.
- `"drop"`: an empty rule set compiles to a **single terminal drop rule**
  (`Action::Block`, no flow criteria, reserved id `FAIL_CLOSED_RULE_ID =
  u32::MAX`, lowest priority).

The decision is applied in `DesiredConfig → DesiredState` (`TryFrom`,
`balansir-control::provider`), i.e. at config-compile time on the control
plane. The daemon/planner/executor see an ordinary one-rule desired state:
the planner diff handles it like any rule, the executor installs a
chain-level drop. No executor change, no planner change, no second authority.

The flag only affects an *empty* rule set. A config with any rules is
compiled exactly as before.

## Consequences

- An appliance can choose fail-closed for safety: an operator who deletes the
  config file gets a terminal drop instead of silently passing traffic.
- The default stays fail-open (`pass`), so existing configs and the current
  reconcile-not-replay model are unaffected.
- The mechanism remains non-authoritative: the fail-closed rule is ordinary
  desired state, invented by the config compiler — not an executor default.
- The reserved id `FAIL_CLOSED_RULE_ID` is `u32::MAX`; a user rule using that
  id would collide, which the strict config compiler does not special-case.
  Documented here; a validation rule could reject it later if needed.
- Packaged appliance profiles can set `[policy] empty_config_action = "drop"`
  (see `DEPLOYMENT_RESEARCH.md`); the general image keeps `"pass"`.

## Verification

- `empty_config_defaults_to_pass`: empty config → no rules.
- `empty_config_fail_closed_installs_terminal_drop`: empty config + `drop` →
  one rule, id `FAIL_CLOSED_RULE_ID`, action `Block`.
- `fail_closed_does_not_touch_non_empty_config`: `drop` with rules → unchanged.
- `empty_config_action_parses_from_toml`: `[policy] empty_config_action =
  "drop"` (lowercase) parses; absent → `Pass`.
- Workspace 18 suites, clippy 0, fmt clean; x86_64 + aarch64 Linux check pass.

## Relation to other gates

- Resolves the gate's P1 product decision.
- Keeps the executor non-authoritative (A1/A2/A3 constraint): the drop rule is
  planner-visible desired state.
- The reserved id interacts with the A2 inventory only through normal
  reconcile: if the drop rule is present in the kernel and later removed from
  desired, it is removed like any other rule.
