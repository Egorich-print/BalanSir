# ADR-026: B4 production observation + controlled execution (P7.2)

## Status
Accepted (P7.2)

## Context

P7.1 (ADR-025) proved the B4 runtime loop as a pure, testable engine with an
injected observer. P7.2 is the step from architecture to real I/O: a **real
closed loop** —

```text
observation → classification → policy decision → bounded adaptation → new observation → recovery / strict failure
```

— without breaking the daemon's authority, without MITM, and with every change
passing through the ownership/reconciliation model (P4.1). The approved
mission (owner's P7.2 spec) forbids: new transport, VPN protocol,
Path/Session/Mechanism, packet interception, stealth classifier, DPI-evasion,
ML, P2P/discovery, BTP.

## Decision

Wire the P7.1 engine to reality through the **existing** boundaries:

1. **Observation — host-stack only, daemon-side:**
   - `b4_engine::host::HostStackObserver` reads the host TCP table
     (`/proc/net/tcp{,6}` on Linux) for retransmission/reset/timeout signals
     per path; on non-Linux it honestly reports unknown (no fake signals).
   - `CompositeObserver` merges that with the DNS plane: `dns_ok` comes from
     the existing `DnsRegistry` (P6) — no second DNS authority.
   - No MITM, no payload inspection, no packet interception.

2. **Execution — through the existing executor boundary (no new authority):**
   - New IPC ops on the existing allowlisted executor: `SetPathMtu`,
     `RestorePathMtu`, `GetPathMtuState`.
   - The executor owns a `PathMtuStore` (applied per-path MTU, keyed by path;
     **per-path, never a global interface setting**). A `PathMtuApplier` is the
     privileged hook; `RecordOnlyApplier` is the honest no-op when no privileged
     mechanism is wired — the executor reports the requested state without
     pretending a kernel change happened.
   - `ExecutorAdapter` gains default methods for these; `ExecutorClient`
     round-trips them over the existing IPC.

3. **Controller — daemon-side adapter under the daemon's authority:**
   - `b4_engine::controller::B4Controller` runs the engine per flow and executes
     decisions: `AdaptMtu` → `executor.set_path_mtu`; `Recovered` →
     `restore_path_mtu` (rollback); `UseFallback`/`FailStrict`/`SwitchDnsPath`
     are logged/recorded (fallback and DNS-path remain policy/plane concerns).
   - The controller records the daemon's **intent** (`intended_mtu`).

4. **Ownership (P4.1) — B4 never changes something the daemon does not know:**
   - `PathMtuReconciler` converges the executor's *reported* MTU state to the
     daemon's *intent*: applies missing, restores extra, idempotently. It runs
     in the same loop as the controller, over the same `ExecutorAdapter` the
     reconcile/ownership path uses.

5. **Strict semantics enforced:** when the allowed adaptation does not help, the
   engine moves to a defined policy state (`StrictFail`) — it does not invent a
   next bypass. Fallback is only ever chosen when the profile explicitly allows
   it.

The daemon (main.rs) spawns the controller loop when `BALANSIR_B4_CONFIG` is
set, driving configured + observed flows and reconciling MTU intent each cycle.

## Consequences

- The B4 closed loop is now real end-to-end: host-stack observation → classify
  → policy-bounded adaptation → re-observe → recovery/strict-fail, executed
  through the same executor boundary the daemon already commands.
- **No new authority.** The controller executes engine decisions derived from
  policy; the executor stays a dumb mechanism; the daemon remains the single
  control-plane authority (A-series + ADR-013/024).
- **Ownership holds.** Any MTU applied by B4 is recorded as the daemon's intent
  and reconciled against the executor's report — B4 cannot make an invisible
  change.
- **Per-path, reversible, bounded.** MTU is keyed by path; `Recovered` rolls it
  back; the reconciler converges drift; no global interface changes without
  explicit policy.
- **Observation is honest.** Non-Linux reports unknown; `RecordOnlyApplier`
  reports requested state without faking kernel application; the privileged
  Linux applier is the P7.3/4 hook.
- VPN is not introduced; fallback is only policy-authorized; STRICT is default.

## Verification

- `PathMtuStore`: set/update/restore round-trip; failed applier does not record.
- Executor dispatch: `SetPathMtu`/`GetPathMtuState` allowlisted; DummyExecutor
  honestly errors; state empty.
- `ExecutorClient` IPC round-trip: daemon sends `SetPathMtu`, queries
  `GetPathMtuState` over a paired authenticated stream.
- `B4Controller`: MTU symptom → applies MTU and records intent; reconciler
  applies intent, removes drift, is idempotent.
- `CompositeObserver`: DNS status observed from the registry.
- Engine tests (P7.1) unchanged; STRICT-fail / SAFE-fallback semantics intact.
- Workspace 18 suites, clippy 0, fmt clean; x86_64 + aarch64 Linux check pass.

## Relation to other gates

- **P7.3** (next): wire the privileged `PathMtuApplier` (route-level MTU/MSS)
  and real netns tests. **P7.4**: B4 ownership/crash-recovery hardening.
- The hard STOP rule holds: if P7.3 requires Path/Session/Mechanism/a new
  authority/persistent B4 store/a scheduler/a transport abstraction, the next
  step is an ADR, not a code extension.
