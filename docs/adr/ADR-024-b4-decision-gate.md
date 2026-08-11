# ADR-024: B4 Architecture — decision gate (P7.0)

## Status
Proposed — **awaiting owner decision** (P7.0 human gate). No production code
changed; the existing `b4.rs` stub is untouched.

## Context

The roadmap requires a human gate before B4 implementation: B4 is the first
part where a wrong abstraction (e.g. a `B4Strategy` enum + external `b4`
binary, which already exists in `b4.rs`) would be costly. P7.0 research
(`docs/B4_ARCHITECTURE_RESEARCH.md`) defines the minimal architecture. This
ADR records the research outcome and the specific decisions the owner must
make.

## Research outcome (verified against code)

- Current B4 (`b4.rs`) is a process-launch stub: `B4Config`/`B4Strategy` enum
  (Fragmentation, TtlDisorientation, FakePacket, HostReplace), an external
  `b4 -c <json>` binary, wired via `ConfiguredFactory`/`DriverLifecycleManager`
  (ADR-011) with `Capabilities::PACKET_PROCESSOR`. It has **no connection** to
  the policy compiler (P5), DNS plane (P6), ownership loop (P4.1), or nft
  executor (M3.7). It is the anti-pattern the research flags for replacement.
- B4 is defined as a **policy-controlled connectivity adaptation layer**:
  *how* to deliver a flow the policy already admitted, under current network
  conditions. Policy stays above B4; B4 never becomes an authority.
- Three independent concerns: classification (what's happening), adaptation
  (what can change), recovery (what to do when a mechanism fails).
- VPN is one mechanism, not the default.
- Observation must be host-stack-only (TCP_INFO, DNS plane, connect error
  classes, byte counters) — no MITM, no payload reads.

## Decisions required

| # | Decision | Options | Research default |
|---|---|---|---|
| D1 | B4 definition | accept "adaptation layer, policy above" vs redefine | accept |
| D2 | Placement | A) daemon-side adapter (planner → B4 → executor) vs B) executor-side | **A** (keeps executor dumb, ADR-013) |
| D3 | Observation scope | host stack only vs broader | **host stack only** |
| D4 | STRICT/SAFE/DEFAULT semantics | final semantics (Section 7 of research) | *owner must pick; agent did not* |
| D5 | P7.1 scope | bounded list (policy interface, observation, capabilities, state machine, config, metrics, testing) vs broader | **bounded; no Path/Session/Mechanism/BTP** |
| D6 | First P7.2 mechanism | adaptive MTU + DNS-path on the direct path vs other | **adaptive MTU + DNS-path** |

## Consequences (if approved)

- P7.1 is a large autonomous mission with the bounded scope above.
- The legacy `b4.rs` stub is replaced, not extended.
- B4 composes onto the existing chain without a new authority:
  `Policy → Compiler → DesiredState → Planner → Reconcile → B4 → executor → nft`.
- The first mechanism (P7.2) is taken end-to-end
  (`detect → activate → verify → monitor → recover → deactivate`) before any
  second mechanism, and before any Path/Session abstraction (P8 rule).

## Rejected (explicitly deferred)

- BTP, `trait Mechanism`/`Path`/`Session` abstractions, discovery network,
  P2P, ML — until real B4 invariants emerge from an implemented mechanism.
- MITM-based observation and any "undetectable transport" promise.

## Verification

- Research document grounded in the current code (Section 0 of
  `B4_ARCHITECTURE_RESEARCH.md`).
- No production code changed by this ADR; workspace gate remains green from
  P4–P6 (18 suites, clippy 0, fmt clean).
