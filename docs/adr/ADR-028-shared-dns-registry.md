# ADR-028: Shared DNS observation authority (P7.2.2)

## Status
Accepted (P7.2.2)

## Context

P7.2 (ADR-026) wired the B4 controller with a `CompositeObserver`, and P6
(ADR-023) uses a `FlowCompiler` fed by a `DnsRegistry`. In the daemon's
composition root (`main.rs`) there were **two independent `DnsRegistry`
instances**: one created for the P6 flow compiler/DNS-resync loop, and a
second created inside the B4 block for the `CompositeObserver`.

Two registries = two independent DNS observation truths: a DNS observation
written to one would be invisible to the other. P6 could compile a domain to
IPs that B4 does not know about, and vice versa — a latent divergence exactly
like the ack-gap/orphan problems the A-series gates eliminated.

## Decision

Make the `DnsRegistry` a **single shared instance** in the daemon composition
root, and share it with both consumers:

- `main.rs` creates exactly one `dns_registry` (`Arc<DnsRegistry>`).
- The P6 `FlowCompiler` receives `(*dns_registry).clone()` — a `DnsRegistry`
  clone that shares the same inner `Arc<Mutex<HashMap>>` (the type is
  `Clone` by Arc-sharing its state).
- The B4 `CompositeObserver` receives `Arc::clone(&dns_registry)` — the same
  instance, no second constructor.
- The second `DnsRegistry::new` in the production path is removed.

`DnsRegistry` (dns_flow.rs) is already `Clone` via an inner `Arc`; this ADR
does not change that type's semantics, only the daemon's composition.

## Consequences

- **One registry = one DNS observation truth.** Any observation written to the
  registry (by a future DNS feed) is read identically by the P6 flow compiler
  and by the B4 observer.
- No way to construct two independent DNS truths in the production path: the
  single `DnsRegistry::new` in `main.rs` is the only production constructor.
- Ownership/reconcile semantics unchanged: `DnsRegistry` remains
  non-authoritative observation state; the daemon remains the authority.
- No real DNS forwarder, no MITM, no new DNS authority, no B4 redesign, no new
  transport (owner's P7.2.2 exclusions).

## Verification

- `shared_registry_is_single_observation_truth` (daemon): one registry shared
  by `FlowCompiler` + `CompositeObserver`. Before insert: P6 compiles nothing,
  B4 sees `dns_ok=false`. After insert: P6 compiles one rule per IP, B4 sees
  `dns_ok=true`. After remove: both revert. Proves the same observation is
  seen by both consumers.
- Grep audit: `main.rs` is the only production `DnsRegistry::new`; all other
  occurrences are in `#[cfg(test)]` modules (reconciler, dns_flow, host).
- Startup/reload/restart behavior unchanged (P7.2.1 tests still green; the
  registry is created before both the P6 loop and the B4 block, so ordering is
  preserved).
- Workspace 18 suites, clippy 0, fmt clean; x86_64 + aarch64 Linux check pass.

## Relation to other gates

- Prerequisite for P7.3 (privileged MTU on real Linux hardware): B4 now reads
  the same DNS truth as the rest of the daemon.
- Explicitly **not** P6.1 (real DNS forwarder): the registry remains empty
  until an observation feed exists; that is a separate milestone.
