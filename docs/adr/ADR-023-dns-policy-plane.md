# ADR-023: DNS policy plane — resolution tracking (P6)

## Status
Accepted (P6, first increment)

## Context

A3 (ADR-018) introduced the `DnsRegistry` and `FlowCompiler`: a desired rule
carrying `flow.dst_domain` is expanded at `set_desired`/`reload` into one
concrete per-IP rule per resolved address, each with a stable derived id. The
roadmap's P6 ("DNS policy plane") asks for DNS to become a central component:
domain policy → IP set → nft rule, so that `youtube.com → DIRECT` compiles
without packet inspection.

The gap: compilation happened **once per reload**. If the DNS observation feed
(the forwarder, or an external resolver) later updated the registry with a
changed IP set, the daemon would keep enforcing the stale resolution until a
manual reload.

## Decision

Track the **raw (authored) desired state** separately from the compiled one,
and re-compile it periodically:

- `Reconciler` keeps `desired_raw` (the pre-compilation state, domains still
  present) alongside the compiled `desired_state`.
- `set_desired`/`reload` store the raw state and compile it as before.
- New `dns_resync()`: re-runs the flow compiler over the raw state; if the
  result differs from what is currently loaded (because DNS observations
  changed a domain's IP set → different derived ids), swaps it in and
  reconciles. Returns whether it changed.
- New `dns_loop()`: a background task calling `dns_resync()` every
  `dns_resync_interval_secs` (default 60; `0` disables).
- The `flow_compiler` moves behind a `tokio::sync::Mutex` so it can be
  registered after construction (the daemon holds the reconciler in an `Arc`);
  `with_flow_compiler` is now `&self`.
- `DesiredState` gains `PartialEq` (and `DesiredDriver` too) so change
  detection is structural, not hash-based.

The daemon now builds a shared `DnsRegistry`, registers a `FlowCompiler` on the
reconciler, and spawns both the ownership loop (ADR-020) and `dns_loop`.

## Consequences

- Domain-based rules track DNS changes without a manual reload: the compiled
  per-IP rules (and their derived ids) follow the latest resolution.
- Change detection is structural (`DesiredState: PartialEq`), so an unchanged
  resolution is a cheap no-op — the periodic pass only reconciles when the
  compiled set actually differs.
- The executor remains domain-free and non-authoritative; only the daemon
  resolves domains (unchanged from ADR-018).
- The nft-**set** optimization (one named set per domain instead of one rule
  per IP) is deliberately **not** implemented here: it would extend the
  reconcile contract (sets are not rules) and cannot be integration-tested on
  the host build. This ADR is the control-plane half of P6; the mechanism half
  is a separate decision when a privileged environment is available.

## Verification

- `dns_resync_tracks_domain_resolution_change`: initial resolution installs
  one rule; the registry is updated to a different IP; `dns_resync()` detects
  the change, the derived id changes, and the kernel converges to the new rule
  (old derived id removed). A second resync with no change is a no-op.
- Existing A2 ownership-loop and A3 domain-compile tests pass unchanged.
- Workspace 18 suites, clippy 0, fmt clean; x86_64 + aarch64 Linux check pass.

## Relation to other gates

- Builds on **A3/ADR-018** (registry + compiler) and the ownership loop
  **ADR-020** (the two loops share the reconcile authority).
- Feeds **P7 B4**: DNS-resolved IP sets are the cheap, inspectable way to
  route `domain → direct/B4/VPN` without packet inspection.
- The nft-set mechanism (P6 second half) remains open for a privileged target.
