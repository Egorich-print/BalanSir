# ADR-025: B4 foundation — runtime loop and first mechanism (P7.1)

## Status
Accepted (P7.1, approved via ADR-024 decision gate)

## Context

ADR-024 approved B4 as a **policy-controlled connectivity adaptation layer**
(placement A: daemon-side adapter), with host-stack-only observation, STRICT
as the default fail semantic, and a first mechanism of **adaptive MTU +
DNS-path** — proving the B4 runtime loop before any "DPI bypass" technique.

The research also flagged the existing `b4.rs` stub (hardcoded `B4Strategy`
enum + external `b4` binary) as the anti-pattern to replace, and set a hard
rule: **no `Path`/`Session`/`Mechanism`/BTP abstractions** until real B4
invariants emerge from a working mechanism.

## Decision

Introduce a pure, testable B4 engine (`daemon::b4_engine`), replacing the
stub's role as the adaptation layer (the legacy `b4.rs` driver is left
untouched and out of this path):

- **policy.rs** — `B4Profile { capabilities, fail, allow_direct, allow_tunnel }`
  and `B4Policy { flows }`. The default profile is **Strict, direct allowed,
  no tunnel, no capabilities**. Policy is authored above B4 and consumed by
  it; B4 never invents policy.
- **observe.rs** — `B4Observation` (connect latency, RTT/RTTvar,
  retransmissions, throughput, DNS ok, reset/timeout, MTU symptom) and the
  `B4Observer` trait. Host-stack-only (no MITM, no payloads). `NoopObserver`
  reports unknown until a real TCP_INFO/DNS observer is wired (P7.2).
- **classify.rs** — deterministic `classify(obs) → B4Class`
  (direct/degraded/interfered/blocked/unknown), with an explicit precedence
  (reset/timeout and MTU symptom = interference; DNS failure = interference;
  retrans/RTT/throughput = degraded).
- **state.rs** — `B4Engine` runtime loop and per-flow FSM
  (idle → observing → adapting → monitoring → recovered/fallback/strict-fail).
  Adaptation within policy bounds: MTU reduction on an MTU symptom, DNS-path
  switch on DNS failure, bounded attempts, then recovery — fallback only when
  policy allows (`allow_tunnel`, or `allow_direct && fail != Strict`), else
  **strict fail** (never a silent downgrade). The engine holds no connection
  and performs no I/O; observations are injected.
- **config.rs** — `B4Toml` strict TOML loading of engine + flow policy
  (`BALANSIR_B4_CONFIG`), converting flat flow entries into `B4Profile`s.
- **main.rs** — optional B4 engine spawn (Noop observer, decisions logged)
  when `BALANSIR_B4_CONFIG` is set; fully disabled otherwise.

The engine emits `B4Decision`s (`Noop / AdaptMtu / SwitchDnsPath / UseFallback /
FailStrict / Recovered`) for the daemon to execute. Execution of MTU/DNS-path
changes (the privileged mechanism step) is explicitly **P7.2**, not this ADR:
this ADR proves the runtime loop and policy/observation/classification model.

## Consequences

- The B4 runtime loop is proven and unit-testable without any privileged
  environment (18 tests: healthy→recovered, MTU symptom→AdaptMtu,
  reset/timeout→StrictFail for Strict, SAFE+direct→UseFallback, disabled
  engine only classifies; policy matching; TOML parsing/rejection).
- STRICT is the default; a flow with no allowed fallback fails rather than
  silently bypassing — the "fallback is part of policy" rule is enforced.
- No `Path`/`Session`/`Mechanism`/BTP; no connection ownership; no second
  authority. B4 decides *how*, policy decides *what*.
- The legacy `b4.rs` enum-stub is not extended; the new engine supersedes its
  role once the P7.2 observer/mechanism is wired.
- B4 is off by default (no config → engine not spawned); enabling it is
  explicit and observable.

## Verification

- `b4_engine` unit tests (policy, classify, observe, config, FSM) — 18 tests.
- Workspace 18 suites, clippy 0, fmt clean; x86_64 + aarch64 Linux check pass.
- Example config `config/b4.toml` parses via `B4Toml::parse`.

## Relation to other gates

- Implements the ADR-024 decision gate (D1–D6 approved).
- P7.2 (next): wire a real host-stack observer (TCP_INFO/DNS) and execute
  MTU/DNS-path decisions through the privileged executor. P7.3: connect the
  B4 policy to the existing policy compiler so B4 flows are derived from
  policy. This ADR stops at the runtime loop.
- The hard STOP rule holds: if P7.2 requires `Path`/`Session`/`Mechanism`/a
  new authority/persistent B4 store/a scheduler/a transport abstraction, the
  next step is an ADR, not a code extension.
