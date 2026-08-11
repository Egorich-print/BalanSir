# ADR-014: M3.7 Datapath v0 — fwmark + ip-rule Enforcement

## Status
Proposed (M3.7 architecture spike — awaiting human approval before implementation)

## Context

BalanSir has a coherent control plane (Policy → Planner → Reconciler →
ExecutorClient → executor → privileged mechanism, ADR-013) but **no packet
datapath**: no packet ever reaches `PolicyEngine::evaluate`; nothing connects
policy decisions to real traffic. M3.7 is the first milestone where
"enforcement" may be claimed.

This spike answers: which Linux datapath mechanism to build first, and exactly
what it can truthfully enforce.

## Verified facts (spike evidence)

### 1. Two disconnected policy representations

- `PolicyRule` (`policy/mod.rs:23-31`) carries a full `Matcher`
  (`DomainSuffix`/`DomainExact`/`IpRange`/`Port`/`Protocol`/`Interface` +
  combinators) and an `Action`. It is used **only** by `PolicyEngine::evaluate`,
  which is **never called from production** (grep: zero non-test callers).
- `DesiredRule` (`types.rs:402-407`) is `{ id, action, priority }` — **no
  matcher**. The planner diff operates on `DesiredRule` and emits
  `UpdatePolicy(DesiredRule)` / `RemovePolicy(id)`.
- `ActionRequest` (daemon→executor payload, `types.rs:335-346`) carries
  `{ action, src_ip, dst_ip, src_port, dst_port, protocol, interface, trace }`.

**Implication:** the reconciliation/executor path is **flow/rule-level**
(`DesiredRule`), not per-packet. The per-packet `PolicyEngine`/`PacketContext`/
`DecisionTrace`/`correlation_id` API is currently library/test-only and is
**NFQUEUE-shaped** — it anticipates a userspace packet path that does not exist.

### 2. Matcher vocabulary vs kernel-level enforcement

`Matcher` includes `DomainSuffix`/`DomainExact` (matched via `domain_hash` in
`PacketContext`). Domain names are a **DNS-layer concept resolved in userspace**;
a kernel datapath (nftables/ip-rule) cannot match a flow by domain name without
first pinning the domain to IPs (a DNS-resolution/compile step). This is the
central constraint on the datapath choice.

### 3. Existing mechanism surface

- `NftablesBackend` (`executor/nftables.rs`): `init`, `add_rule(NftRuleSpec)`,
  `flush`, `list_rules`. `NftRuleSpec` = `{ proto, src_cidr, dport, verdict }`.
- Executor maps `Action::Allow → Accept`, `Action::Block → Drop` in nft;
  everything else (`Route`/`Mark`/`Forward`/`Shape`) is `Unsupported` today
  (`service.rs:37-45`).
- `rtnetlink` 0.14.1 (already a daemon dependency, `daemon/Cargo.toml`)
  exposes `rule()` with `fw_mark()` and route management — fwmark/ip-rule is
  implementable with the existing dependency, no new netlink stack.
- `netlink.rs` (daemon) currently supports link/address/route ops.

## Decision

### Primary mechanism: **fwmark + ip-rule** (nft classification → mark → policy-routing)

The datapath is:

```
nft classification rule
   (match proto/ip/port/interface)
        │
        ▼
   meta mark set N          (nft: fwmark)
        │
        ▼
   ip rule add fwmark N lookup <table>     (policy routing)
        │
        ▼
   <table> default route                   (mechanism selection: DIRECT / VPN / drop)
```

Mapping from the existing `Action` vocabulary:

| Action | Kernel enforcement |
|---|---|
| `Allow` | no mark → default table (direct), or explicit accept rule |
| `Block` | mark → drop (or `meta mark set N` + table with null route) |
| `Reject` | nft `reject` (ICMP unreachable) |
| `Mark { fwmark }` | nft `meta mark set N` |
| `Route { table }` | `ip rule add fwmark N lookup <table>` + route in table |
| `Forward { driver }` | table route via the driver's interface (M3.5 factory) |
| `Shape`/`Log` | deferred (no tc/QoS in M3.7) |

This maps naturally onto `Action::{Mark, Route}` and reuses `NftablesBackend`
(extended to emit `meta mark set`) + `rtnetlink::rule()`.

### Why not NFQUEUE (deferred, not chosen)

- NFQUEUE is **per-packet userspace round-trip**: the kernel queues packets to
  the daemon, `PolicyEngine::evaluate(PacketContext)` decides, a verdict is
  returned. It is the only way to enforce **domain-name** policy directly.
- It is higher complexity, has throughput/latency cost, requires a userspace
  packet-processing loop, and there is **no demonstrated product requirement
  for per-packet inspection today**.
- The existing `PacketContext`/`DecisionTrace`/`correlation_id` API is
  NFQUEUE-shaped but unused; keeping it library-only is honest.

**Decision:** fwmark + ip-rule is chosen **for the flow-level subset that
`DesiredRule`/`ActionRequest` can express today**. NFQUEUE is explicitly
deferred; it becomes a candidate only if domain-level per-packet policy becomes
a hard requirement (separate decision).

### Critical honesty boundary

M3.7 enforces **what the reconciliation path can express**: flow-level rules
(proto/ip/port/interface + `Action`) via `DesiredRule` → `UpdatePolicy` →
`ExecutorClient` → nft mark/rule. It does **not** claim to enforce
`PolicyRule` domain matchers — `PolicyEngine` remains the decision *authority*,
and wiring the *per-packet* evaluate path is out of M3.7 scope unless the
planner begins emitting matcher-carrying operations.

## Consequences

### Packet classification
Classification lives in **nft rules installed by the executor** (compiled from
`DesiredRule`/`ActionRequest`), not in a userspace loop. The daemon remains the
sole authority; the executor is dumb (it applies the rules it is told).

### No PolicyEngine bypass
Enforcement derives from the same `DesiredRule`/`ActionRequest` the planner
produces. There is no second decision engine. `ALLOW` remains an explicit
decision (a rule/treatment), not an escape.

### IPv4/IPv6
`ActionRequest.src_ip/dst_ip` are `[u8;4]` (IPv4 today). IPv6 is deferred: the
datapath rule rendering must key off `ActionType`/address family, but no IPv6
field exists yet in `ActionRequest` — documented, not invented.

### Routing tables
fwmark+ip-rule needs route tables. Minimal: one table per distinct
`Route{table}`/`Forward{driver}` target (or reuse default table for DIRECT).
Table identifiers map 1:1 from `Action` — no new table-discovery model.

### Rollback
Unchanged (ADR-010/011): the daemon's reconcile FSM is the transaction boundary.
On failure the daemon rolls back via existing `Snapshot`/`Rollback`; the
executor applies only the plan it is sent. Removing a rule = the executor's
`RemovePolicy`/flush on the affected table.

### Fail-open / fail-closed
Not decided here (product semantics, §9 of the mission). The datapath must
preserve whatever `default_action()` the PolicyEngine configuration selects
(already exists) — it must not hardcode fail-open. If strict/fallback product
semantics are required beyond existing config, that is a separate decision.

### Connection loss
Executor unreachable → `ExecutorClient` fails → reconcile rolls back → daemon
reconnects and recomputes `Desired − Actual` (ADR-013). No replay.

### Namespace/interface ownership
The executor operates on the host default netns today. Network-namespace
isolation is out of M3.7 scope (documented future capability; not invented).

### Testability
- Unit: nft rule rendering (mark emission), `rtnetlink::rule()` request
  building, mapping `DesiredRule`/`ActionRequest` → kernel state.
- Integration (environment-gated): real `nft`/`ip rule`/`ip route` application
  in a privileged test netns when the environment allows; otherwise honest
  "environment unavailable" documentation — never a fabricated `Applied`.
- Reconcile rollback of installed rules.

### MTU
Future boundary only: MTU is a path/session property (ADR-012 spirit), not part
of the fwmark datapath. Not implemented.

## Explicit non-goals (M3.7 spike)

- No NFQUEUE, eBPF, tc/QoS, DPI, packet-inspection framework.
- No domain-matcher enforcement in the kernel (requires the deferred path).
- No BTP/Path/Session/ML.
- No network-namespace ownership model.
- No IPv6 until `ActionRequest` carries an address family.
- No fail-open/fail-closed product semantics beyond existing config.

## Migration path (for M3.7 implementation, after approval)

1. Extend `NftRuleSpec`/`NftablesBackend` to emit `meta mark set N` and route
   table output (typed, no shell).
2. Add an executor operation path that maps `DesiredRule`/`ActionRequest` →
   nft mark + `rtnetlink::rule().add().fw_mark(N)...` + table route.
3. Wire it behind the existing allowlist (`AddRule`/`RemoveRule`/`FlushRules`);
   remove the M3.6 `RemoveRule not yet implemented` placeholder only when
   handle-based removal is real.
4. Daemon `ExecutorClient` sends these ops from the reconcile path (replace
   `PendingMechanismAdapter` where flow-rule ops exist); keep planner/authority
   unchanged.
5. Environment-gated integration tests for nft + ip-rule application.

## Verification (on approval)
- Host: `cargo test --workspace`, clippy, fmt.
- Linux: x86_64 + aarch64 + riscv64/musl CI.
- Privileged test (when runner permits): nft mark rule installed, `ip rule`
  reflects it, reconcile rollback removes it.
- Adversarial audit: no PolicyEngine bypass, no second planner, executor stays
  dumb, no datapath mechanism forced by a nonexistent requirement.

## Decision record
fwmark + ip-rule is the M3.7 first datapath, limited to the flow-level subset
`DesiredRule`/`ActionRequest` can express. NFQUEUE is deferred (no demonstrated
per-packet need). Domain-matcher enforcement and MTU/IPv6/netns remain future
boundaries. Awaiting human approval.
