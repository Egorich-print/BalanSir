# ADR-018: Flow-level policy (DNS/conn metadata → compiled nft rules)

## Status
Accepted (Architecture Gate A3)

## Context

Gate v1 §9 (A3) recorded that enforcement was **chain-level verdict**, not
per-flow: `DesiredRule` had no matcher, so `apply_rule` sent all-zero flow
fields and every installed rule matched every packet. There was no per-flow
packet path and no bypass — but a firewall that can only drop/allow whole
chains cannot express "block this destination port", let alone "block this
domain". A4 (ADR-017) made IPv4/IPv6 addresses representable in the wire
contract; A3 is the decision about how flow criteria get from policy into
compiled kernel rules.

The gate also names the compilation source: **DNS/conn metadata → compiled
nft rules**. The daemon has a `DnsForwarderDriver` stub but no observation
feed that turns "domain X" into a set of addresses a rule can match.

## Decision

Introduce **optional flow criteria on desired rules** and compile them into
per-flow nft rules at two stages:

1. **Static criteria (config → kernel):** `DesiredRule` gains
   `flow: Option<FlowCriteria>` where `FlowCriteria = { src_ip, dst_ip,
   src_port, dst_port, protocol }` (all optional; `None`/unspecified/0 =
   "any"). The TOML `RuleConfig` accepts the same fields. `apply_rule` maps
   them into `ActionRequest` (already IpAddr-carrying after A4), and the
   executor compiles them into `NftRuleSpec` matchers: `ip|ip6 saddr`,
   `ip|ip6 daddr`, `th sport`, `th dport`, `meta l4proto`. Family is derived
   from each address (`ip6` when the CIDR contains `:`).

2. **DNS/conn metadata (domain → IPs):** a `DnsRegistry` (in-memory
   `domain → Vec<IpAddr>`, populated by the DNS forwarder/observation feed)
   plus a `FlowCompiler`. A desired rule carrying `flow.dst_domain` is
   expanded at `set_desired`/`reload` into one concrete per-IP rule per
   resolved address, each with a **stable derived id** (FNV-1a over
   `(base_id, ip)`). The domain field is cleared before the executor ever
   sees a rule; an unresolved domain compiles to nothing (not enforced until
   it resolves).

The planner treats flow criteria as part of rule identity: `StateDiff`
compares `id + action + flow`. Same id with a changed flow is an `UpdatePolicy`
(ADR-015 makes the re-apply idempotent); unchanged flow is a `NoOp`. This
keeps the single-planner model (M3.4.2): the daemon compiles, the planner
diffs compiled rules, the executor only installs.

## Consequences

- Rules can now match on source/destination address, ports, and protocol —
  the flow-level policy fork named in the gate is closed.
- Domain-based policy is compiled to concrete IP rules by the daemon; the
  executor remains non-authoritative and domain-free.
- A resolved domain change produces different derived ids → the planner
  removes stale per-IP rules and installs new ones on the next reload, with
  no executor-side logic.
- The postcard wire shape of `DesiredRule`/`ActualRule` changes (new `flow`
  field, always encoded so postcard round-trips are stable). Daemon and
  executor upgrade together.
- `ActualRule.flow` records the installed criteria so the planner can detect
  drift; the A2 inventory seeds chain-level rules with `flow: None` (they are
  only matched for orphan removal by id).
- `flow` is `Option`al and defaults to `None`: existing chain-level configs
  keep working unchanged (an all-`None`/absent flow compiles to no matcher).

## Verification

- `flow_criteria_change_triggers_update` (common diff): same id + different
  flow → UpdatePolicy; same flow → NoOp.
- `test_flow_rule_render_v4_and_v6` (executor nft): full flow rule renders
  `ip saddr/daddr`, `th sport/dport`, and the v6 variant uses `ip6`.
- `nft_spec_renders_ipv6_src_as_ip6_saddr`, `test_matcher_ip_range_v6`,
  `test_cidr_parsing_v6` (A4) continue to pass.
- `domain_rule_compiles_to_one_rule_per_ip`, `domain_rule_is_deterministic`,
  `no_domain_rule_passes_through` (daemon dns_flow): one rule per resolved
  IP, stable derived ids, domains never leak to the executor, unresolved
  domains drop.
- Provider: `RuleConfig` accepts `src_ip/dst_ip/src_port/dst_port/protocol/
  dst_domain`; strict compile rejects bad addresses/protocols atomically.
- Workspace 18 suites, 175 tests, clippy 0, fmt clean; x86_64 + aarch64 Linux
  check pass.

## Relation to other gates

- Builds on **A4/ADR-017** (IpAddr wire fields) and **A1/ADR-015** (idempotent
  re-apply makes flow-changed updates safe).
- The **A2** inventory remains id-based; per-IP compiled rules are ordinary
  flow rules to the planner and executor.
- Product semantics (fail-open vs fail-closed on the whole chain) remain a
  separate product decision, unchanged by this ADR.
