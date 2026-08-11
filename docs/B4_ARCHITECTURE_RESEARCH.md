# P7.0 — B4 Architecture Research

Status: research · **No production code** · Purpose: define the *minimal*
architecture of B4 — a **policy-controlled connectivity adaptation layer for
the Linux datapath** — that lets BalanSir work around DPI without inventing
BTP/Path/Session/Mechanism prematurely and without breaking the authority
model established in P4–P6.

This document is the input to a **human decision gate** (ADR-024). Nothing in
it is a final architecture; the owner reviews and decides before any P7.1
coding mission.

---

## 0. What exists today (grounding, verified in code)

- `DriverId::B4` and a `b4` Cargo feature (default-on) exist since M3.5.
- `crates/balansir-daemon/src/b4.rs` defines `B4Config { mode, ports,
  strategies, upstream }`, `B4Mode { Transparent, Proxy }`, and hardcoded
  `B4Strategy` variants: `Fragmentation`, `TtlDisorientation`, `FakePacket`,
  `HostReplace`.
- `B4Driver` is a `ComponentDriver` that writes a JSON config to
  `/run/balansir/` and spawns an **external `b4` binary** (`-c config`),
  stopping it with `pkill -f balansir-b4-<id>`.
- It is wired through `ConfiguredFactory` → `DriverLifecycleManager` (ADR-011)
  with `Capabilities::PACKET_PROCESSOR`.
- There is **no connection** between B4 and: the policy compiler (P5), the DNS
  plane (P6), the ownership loop (P4.1), or the nft executor (M3.7). B4 today
  is a process-launch stub, not a datapath subsystem.

**This is exactly the "B4Driver architecture trap" the roadmap warns about:**
a fixed `strategy` enum + an external binary, decided before the policy /
observation / failure model exists. P7.0 must define the layer these should
hang off, not refine the enum.

---

## 1. What B4 means

B4 is **not** "one specific DPI bypass". It is the **policy-controlled
connectivity adaptation layer**: it answers *"how do I deliver this flow to
its destination under the current network conditions?"* — but it does **not**
decide *who is allowed to do so*.

```text
PolicyEngine          (authority: decides what should happen)
    ↓
Policy decision
    ↓
B4 selection          (adaptation: how to deliver, given conditions)
    ↓
B4 mechanism          (mechanism: specific Linux datapath technique)
    ↓
kernel / network
```

- **Policy is above B4.** B4 never creates policy, never overrides a decision,
  never becomes a planner. It is a *mechanism selector + mechanism* that the
  daemon's authority drives.
- **B4 is not the executor.** The privileged executor (M3.7, ADR-013) installs
  nft rules under the daemon's authority. B4 must compose *on top of* that
  authority boundary: policy → compiled rules → (some rules engage B4
  adaptation) → kernel. B4 does not get a second command channel to the
  kernel.

### 1.1 The minimal B4 contract (hypothesis)

A flow-level decision from the daemon says: *this flow may use B4 adaptation,
with these allowed mechanisms and this failure semantic.* B4 answers: *which
mechanism, given current observations* — and reports *outcome* back so the
daemon's policy (not B4) decides what next. This keeps B4 as an
**observation + adaptation + recovery executor under policy**, exactly like
the nft executor is an observation + execution mechanism under policy.

---

## 2. Three independent concerns (must be researched separately)

### 2.1 Classification — what is happening to the connection?

States a flow/path can be in, each with evidence:

- **direct** — the normal path is working.
- **direct-but-degraded** — works but lossy/slow/resetty.
- **DPI-interfered** — recognizable interference (reset after a volume/duration
  window, RST injection, blackhole of specific packets, SNI/timing pattern).
- **blocked** — no progress at all.
- **unknown** — not enough signal yet.

**Research question:** which classifications are observable *from the host
without MITM* (Section 4)? Classification must be a **judgment over
observations**, not a packet-inspection feature.

### 2.2 Adaptation — what can be changed?

The mechanism menu (each is a separate, opt-in capability, NOT a monolithic
B4):

- MTU / MSS (Section 6)
- TCP parameters (initial window, retransmission behavior, timestamps)
- DNS path (already have a DNS plane, P6)
- routing (we already compile `Mark`/`Route` — ADR-014)
- transport (direct vs tunnel — Section 3)
- encapsulation / fragmentation strategy
- connection retry / endpoint selection
- SNI / TLS-parameter handling (privacy boundary — Section 9)

**Principle:** every mechanism is a `capability → driver → observable result`
triple (from the roadmap). No "B4 monolith".

### 2.3 Recovery — what if a mechanism doesn't work?

The explicit policy-driven ladder:

- retry (same mechanism, bounded)
- switch mechanism (within B4)
- switch transport (direct → B4 → VPN)
- return to direct
- **strict failure** (fail the connection, do not bypass)

Recovery is **policy-defined** (Section 7 STRICT/SAFE/DEFAULT), not an
emergency `if` inside B4.

---

## 3. B4 does not automatically mean VPN

The key distinction:

```text
YouTube
  ↓
B4
  ↓
direct works        → stay on direct (B4 tuned the direct path)
```

and only if `direct + B4` is worse than a tunnel:

```text
direct + B4 < VPN   → escalate to VPN
```

- **VPN is one mechanism among several** (direct, B4, VPN, B4→VPN), not the
  default transport for every connection.
- B4's first job is to make the **direct** path work better (MTU, TCP, DNS,
  routing), not to tunnel everything.
- The daemon's policy (ADR-018 flow rules) picks the path; B4 only *executes
  adaptation for the chosen path*.

This prevents "everything through VPN" as an accidental default.

---

## 4. Observation model — what Linux can see without MITM

For each connection/flow we would *like* to observe: connect latency,
handshake latency, packet loss, retransmissions, RTT, RTT variance,
throughput, connection reset, timeout, MTU symptoms, DNS success/failure, TLS
establishment, HTTP response behaviour.

**Research finding (the honest list):** many of these are available **without
MITM** from the host, but must be sourced carefully:

| Signal | Source (no MITM, Linux) | Feasible |
|---|---|---|
| connect latency / success | `connect()` timing, TCP stack (`tcp_info`, `SIOCINQ`) | ✅ host-side |
| RTT / RTT variance | `TCP_INFO` (`tcpi_rtt`, `tcpi_rttvar`) | ✅ host-side |
| retransmissions | `TCP_INFO` (`tcpi_retrans`, `tcpi_total_retrans`) | ✅ host-side |
| packet loss (symptom) | retransmission growth + `SS_*` / `netstat`-style stats | ✅ approximate |
| connection reset / timeout | connection error class (`ECONNRESET`, `ETIMEDOUT`) | ✅ host-side |
| throughput | bytes over time (host-side counters) | ✅ host-side |
| MTU symptoms | `EMSGSIZE`, fragmentation counters, `TCP_INFO` pmtu | ✅ host-side |
| DNS success/failure | resolver result (we already have the DNS plane, P6) | ✅ host-side |
| TLS establishment | connect succeeds + TLS ClientHello accepted (handshake timeout) | ✅ without reading content |
| HTTP response behaviour | **requires MITM or proxying** | ❌ not host-passive |
| SNI/timing fingerprint of the *peer's* behaviour | requires observation of the censor | ❌ not on-host |

**Key boundary:** B4 observes what the **host stack** exposes — it does not
MITM traffic and does not read payloads. TLS "establishment" is inferred from
handshake success/failure timing, never by decrypting.

**Recommendation:** build the observation model on **host TCP_INFO + DNS
plane + connect error classes + flow byte counters**. These are the only
signals that are (a) available without MITM and (b) privacy-safe. Everything
else is out of scope for B4 observation.

---

## 5. Warm-up (as its own component, before BTP)

```text
new network
   ↓
warm-up
   ↓
probe direct / B4 / VPN
   ↓
score
   ↓
preferred connectivity strategy
```

Warm-up must NOT mean "send suspicious probes every 10s". Requirements:

- **cheap** — probes are small, bounded, short-lived;
- **bounded** — a strict probe budget (N bytes / M seconds), then a hold-off;
- **adaptive** — learn from history, not a single sample;
- **piggybacked** — prefer observing *real* traffic over synthetic probes;
- **disableable** — `warm_up = false` must be a valid config;
- **privacy-budgeted** — probing must respect the privacy policy (Section 9):
  no probe that leaks more than the real traffic would.

Warm-up produces a *preferred strategy* (a suggestion to policy), never a
security decision. It lives above B4 mechanisms but below the authority.

---

## 6. Adaptive MTU (research now — it is foundational)

```text
path MTU
   ↓
observed fragmentation / EMSGSIZE
   ↓
TCP MSS / pmtu discovery
   ↓
encapsulation overhead (VPN/B4)
```

**Findings:**

- **MTU must be a property of the connectivity path, not a global BalanSir
  setting.** Each path (direct, B4-over-X, VPN-Y) has its own effective MTU.
- Linux already does path-MTU discovery for TCP (`tcp_pmtu_discovery`, cached
  `pmtu`). B4's job is to *read* it (`TCP_INFO.tcpi_mss`/pmtu symptoms,
  `EMSGSIZE` for UDP) and to *set* per-route/per-tunnel MTU, not to re-invent
  probing.
- For TCP: adjust `MSS` per path (the kernel derives it from the route PMTU).
- For UDP/tunnels (WG/QUIC): the encapsulating interface has its own MTU;
  B4 sets it per tunnel.
- Fragmentation: prefer to avoid (DF set) and let PMTU discovery work, rather
  than fragmenting (fragmentation itself is a DPI signal and a privacy leak).

**Placement (from P7.0 perspective):** adaptive MTU is a **mechanism**
(capability) in the B4 adaptation layer. The *policy* only says "this path
should work"; MTU tuning is mechanism detail. This slots into the future BTP
naturally (per-path MTU) without needing BTP to exist.

---

## 7. STRICT / SAFE / DEFAULT (policy semantic — human gate)

Conceptual semantics (NOT to be finalised by the agent):

```text
STRICT   protected path required
         no secure mechanism available
         → connection fails (never downgrade security)

SAFE     secure mechanism preferred
         temporarily unavailable
         → restricted fallback (only explicitly-allowed safer-than-nothing)

DEFAULT  best available connectivity
         → direct may be used
```

**Critical rule:** fallback is **part of policy**, not an emergency `if`.
The allowed fallback ladder for a flow is declared in policy
(e.g. `direct → B4 → VPN`), and B4 executes within that ladder. B4 never
chooses to violate STRICT.

**This is a product/architecture decision for the owner (ADR-024).** The
agent must not pick the final semantics.

---

## 8. Anti-patterns this research must avoid

1. **The B4Driver enum trap** — `B4Strategy { Fragmentation, FakePacket, ... }`
   as a hardcoded driver menu. Rejected: mechanisms are capabilities with
   observable results, selected by B4 under policy, not a compile-time enum.
2. **Premature Path/Session/Mechanism traits** — do not introduce
   `trait Mechanism {}`, `struct Path`, `struct Session` until real B4
   invariants emerge from an implemented mechanism (the roadmap's P8 rule).
3. **Second authority** — B4 must not decide what *should* be (that is the
   planner); it decides *how to deliver a flow the policy already admitted*.
4. **B4 as VPN-by-default** — B4's purpose is to improve the direct path; a
   tunnel is a fallback, not the default.
5. **MITM observation** — B4 observes the host stack, never payloads.

---

## 9. Privacy boundary

B4 and the future privacy layer must not promise "undetectability". B4 may:

- reduce unnecessary leakage (DNS, IPv6, WebRTC-adjacent, telemetry);
- prefer privacy-preserving mechanisms (no cleartext probes beyond what real
  traffic already does).

B4 must **not** attempt to fake GPS/cookies/accounts/browser fingerprint —
that is a different product. The observation model (Section 4) is already
limited to privacy-safe host signals.

---

## 10. Interaction with the existing authority model

B4 composes onto the existing chain without a new authority:

```text
Policy → PolicyCompiler → DesiredState → Planner → Reconcile
                                                        ↓
                                          B4 (adaptation, under policy)
                                                        ↓
                                          privileged executor → nft/kernel
```

Two placement options to decide at the gate (ADR-024):

- **A. B4 as a daemon-side adapter** between reconcile and the executor: the
  planner emits flow rules tagged with an allowed-mechanisms set; the daemon
  selects a B4 mechanism and drives it via the existing executor. Keeps B4 in
  the unprivileged daemon, executor stays dumb. **Preferred hypothesis.**
- **B. B4 as part of the privileged executor**: mechanisms run where the
  kernel work happens. Risk: executor grows policy (violates its role).

Research favors **A**, consistent with ADR-013 (executor = dumb mechanism,
daemon = commander).

---

## 11. Recommended P7.1 scope (for the gate to approve)

If approved, P7.1 (a large autonomous mission) would build only:

```text
B4 policy interface      (allowed mechanisms + fallback ladder per flow)
B4 observation model     (TCP_INFO, DNS plane, connect errors — Section 4)
B4 capability model      (MTU, TCP params, DNS path, routing — opt-in caps)
B4 state machine         (classification → adaptation → recovery)
B4 configuration         (bounded probing, warm-up budget, disableable)
B4 metrics               (per-mechanism outcome, fed to the daemon's metrics)
B4 testing               (deterministic fakes; no privileged env needed)
```

and explicitly **not** build: `Path`, `Session`, `Mechanism` traits, BTP,
discovery network, P2P, ML — unless required by a specific first mechanism.

The first mechanism (P7.2) should be a single, provable one — e.g. adaptive
MTU + DNS-path adaptation on the direct path — taken through
`detect → activate → verify → monitor → recover → deactivate` before a second
mechanism is added.

---

## 12. Decision gate (this is where the agent stops)

The owner decides:

1. **B4 definition** — accept "policy-controlled connectivity adaptation
   layer, policy stays above" (Section 1)?
2. **Placement** — B4 as daemon-side adapter (A) vs executor-side (B)?
3. **Observation scope** — host stack only (TCP_INFO + DNS + errors), no MITM?
4. **STRICT/SAFE/DEFAULT** — final semantics (Section 7, agent did NOT pick).
5. **P7.1 scope** — approve the bounded list in Section 11; reject any
   Path/Session/Mechanism/BTP for now.
6. **First mechanism** — approve adaptive MTU + DNS-path as the first P7.2
   candidate.

No production code was changed by this document. The existing `b4.rs` stub is
untouched; it is flagged as the anti-pattern to be replaced, not extended.
