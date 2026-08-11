# BTP Architecture Research

Status: research · No code, no new traits/crates, no `BtpSession`/`BtpPath`/
`BtpTransport`, no BalanSir changes. Purpose: decide whether BalanSir needs a
BTP ("Balanced Traffic Pathing") layer at all, and if so, how it should be
shaped — by studying existing protocols and architectures, not by designing a
new protocol from scratch.

> Hard constraint: **no code in this document**. Everything below is analysis
> and recommendation. Anything marked "implement later" is a separate decision.

---

## 1. Threat model and BTP's goal

### 1.1 What BTP solves (the real problems)

- **Censorship/DPI blocking** — an upstream (ISP/censorship appliance)
  terminates or corrupts connections once it recognizes the flow as a VPN or
  a disallowed destination.
- **Unstable/degrated channels** — a transport that worked at one moment loses
  throughput or dies after sustained use.
- **Short TCP corridors** — connections that are *reliably* killed after a
  fixed volume or duration (the 16-KB corridor hypothesis, §4).
- **Transport availability drift** — a direct path, a DPI-bypass path (B4),
  and a VPN path each have different reachability at different times.
- **Session continuity** — the user wants an existing session to survive a
  transport change (connection migration), not to restart the app.

### 1.2 What BTP explicitly does **not** solve (honesty boundary)

- **User anonymity** — BTP is not Tor; it does not hide the user from a global
  passive adversary that sees both ends.
- **Endpoint fingerprinting** — a determined attacker with the app binary and
  active probing can recognize the client regardless of transport.
- **GPS / cookie / account-level tracking** — application-level, out of scope.
- **"Undetectability"** — explicitly rejected (§10). BTP may *reduce*
  fingerprintability; it cannot promise invisibility.

### 1.3 Separation of concerns

| Concern | Question | Owner |
|---|---|---|
| Privacy | does the transport leak identity/activity? | crypto + TLS/Noise |
| Censorship resistance | can the transport be blocked reliably? | transport + fingerprinting |
| Reliability | does the session survive transport churn? | migration + warm-up |
| Performance | is latency/throughput acceptable? | selection + MTU |

These must be evaluated independently. A transport that scores well on
privacy may score poorly on censorship resistance (e.g. plain HTTPS to a
known CDN is private-ish but trivially blocked by SNI filtering).

---

## 2. Requirements

### 2.1 Functional

- **Capability discovery** — a node can learn what transports/features a peer
  supports.
- **Session establishment** — a stable session identifier survives transport
  change.
- **Transport negotiation** — pick a transport per session/flow.
- **Endpoint discovery** — learn the peer's reachable addresses.
- **Configuration updates** — policy/transport config can change at runtime.
- **Statistics** — per-transport latency, loss, throughput for selection.
- **Keepalive** — detect silent failure.
- **Graceful migration** — move a session to another transport without data
  loss and without re-handshake overhead.

### 2.2 Non-functional

- **Minimal extra traffic** — control plane must not dominate the data path
  (especially under the 16-KB corridor).
- **Offline operation** — the box must keep enforcing policy when the
  discovery/control server is unreachable (§8).
- **Forward compatibility** — transports come and go; protocol must not hard
  code the transport set.
- **Deterministic fallback** — no pathological flapping (§6).

### 2.3 Hard constraint from the A-series gates

The daemon is the sole authority; the executor is a dumb mechanism. Any BTP
decision that touches the data plane must be expressed as **policy/desired
state** (as ADR-018 did for flows), not as a second planner. BTP research
must therefore ask: *is path selection policy or mechanism?* — and the answer
will shape whether BTP lives in the daemon (policy) or leaks into a new
executor role (rejected unless forced).

---

## 3. Existing protocol comparison (no new protocol design)

| Transport | Latency | HOL blocking | Multiplexing | NAT traversal | Reconnect | Fingerprintability | Deploy complexity |
|---|---|---|---|---|---|---|---|
| **TCP** | base | inherent (stream) | per-conn only | needs STUN/hole-punching | new 3WHS + state | very high (seq/acks, no TLS) | trivial |
| **TLS 1.3** (over TCP) | +1 RTT | inherits TCP | no (one stream) | via TCP | session resumption | moderate (ClientHello shape) | low |
| **HTTP/2** (TLS) | low | mitigated (streams) | yes (multiplexed) | via TCP | connection-level | moderate (SETTINGS, HPACK) | low |
| **HTTP/3 / QUIC** | lowest (0/1-RTT) | none (independent streams) | yes + connection migration **built-in** | excellent (QUIC NAT rebinding) | connection IDs survive addr change | moderate-high (QUIC is distinctive) | medium |
| **WebSocket** (TLS) | +HTTP/2 | inherits TCP | no (single stream) | via TCP | re-handshake | moderate (Upgrade header) | low |
| **gRPC** (HTTP/2) | low | mitigates | yes (many RPCs) | via TCP | connection-level | moderate | medium (protobuf) |
| **ConnectRPC** (HTTP/2+3) | low | mitigates | yes | inherits transport | inherits transport | like HTTP/2 | medium |
| **Existing VPN transports** (WG/AWg/Xray) | low–med | packet-level | yes (tunnels) | varies (WG roaming is built-in) | fast (stateless keys) | **high** (recognizable as VPN) | high (kernel/module or userspace) |

### 3.1 Key findings

- **QUIC/HTTP3 is the only mainstream transport with built-in connection
  migration and NAT rebinding.** If migration matters (§5), QUIC gives it for
  free — no custom migration protocol needed.
- **ConnectRPC** deserves its own note: it is a *control/discovery/session
  protocol* (RPC over HTTP/2+3), not a VPN dataplane. As a control plane it
  gives: typed RPC, streaming, multiplexing, and reuses the transport layer's
  migration. **Recommendation: study ConnectRPC as the BTP *control* transport
  candidate — do not assume it is the data path.**
- Every VPN transport is *recognizable as a VPN* by packet heuristics (§10).
  None of TCP/TLS/HTTP2/QUIC is "invisible"; the question is cost of
  blocking vs cost of running.

---

## 4. 16-KB corridor hypothesis

### 4.1 What the hypothesis claims

A monitored corridor kills a connection after ~16 KB of traffic (or a fixed
short window), plausibly as a DPI rule that targets "sustained tunnel-shaped
traffic" or a fixed byte budget per connection.

### 4.2 Technical plausibility

- **Plausible:** cheap middleboxes can count bytes-per-flow and drop when a
  threshold trips. It is a *volume* heuristic, easy to implement, hard for the
  client to evade without changing the *shape*.
- **But not axiomatic:** there is no evidence that 16 KB is universal. It is
  an operator-specific rule. The right response is **measurement, not
  acceptance** (§4.4).
- **What it is NOT:** it is not evidence that the tunnel protocol is broken —
  it is evidence that *long-lived single connections of recognizable shape*
  are targeted.

### 4.3 Behavior of transports under a hard byte/flow budget

- **TCP/TLS single stream:** a 16 KB budget kills a long download dead;
  reconnect restarts the budget (a "short corridor" of exactly this kind).
- **HTTP/2 multiplexing:** many streams share one connection — a per-*flow*
  budget would kill the whole connection; a per-*stream* budget kills streams
  (which the app could retry on new streams).
- **QUIC:** independent streams on one connection; a per-flow budget kills the
  connection (but QUIC's connection IDs let the app re-establish a *new*
  connection cheaply and migrate — 0-RTT resumption is budget-efficient).
- **Worst case:** a *long single stream carrying a large file* is exactly the
  shape that trips a volume-based rule. Splitting into short, quota-sized
  chunks across new connections/streams defeats a per-flow budget.

### 4.4 The measurement-first stance

The research conclusion: **do not design a protocol around 16 KB.** Instead:

1. Instrument the executor (passive) to observe connection lifetime vs bytes
   (the executor already lists flows; adding byte counters is mechanism-level
   and deferred).
2. Define a *corridor experiment*: fixed payload sizes vs lifetime, run on the
   actual upstream.
3. Only if a volume rule is confirmed, the *transport strategy* (§5) — not the
   protocol — adapts (e.g. chunked sessions under a configurable budget).

### 4.5 Handshake/control under a tiny budget

A handshake must fit in the budget or be resumable:

- TLS 1.3 resumption (PSK) is ~1 RTT and tiny — good.
- QUIC 0-RTT is ~1 RTT and resumable — good.
- A full Noise handshake (3 messages) is fine for *control* traffic which is
  itself small; the problem is only if the handshake must run inside the data
  budget alongside payload.

### 4.6 Mid-message interruption

If a message is split by an interruption:

- Stream transports (TCP/TLS/HTTP2) resend the tail from the interruption
  point after reconnect (no full re-handshake if session resumption is used).
- QUIC resumes via connection ID; the lost tail is retransmitted by QUIC.
- **Recommendation:** keep control messages small (<1 KB) so a single message
  rarely straddles an interruption; resume state is the session ID, not the
  message.

---

## 5. Connection migration / multipath (MPTCP-like, research only)

### 5.1 Model

Conceptually MPTCP, but **without creating `Path`/`Session` entities in
BalanSir**:

- **Multiple transports** available per node (direct, B4, VPN-1, VPN-2).
- **Primary/secondary** — one preferred, others on standby.
- **Migration** — move the session to a different transport.
- **Racing** — try several paths for the first bytes, keep the winner.
- **Fallback** — automatic move on failure.

### 5.2 What already exists (don't build)

- **QUIC connection migration** (RFC 9000) — transport-level, built-in.
- **WireGuard roaming** — IP changes without renegotiation.
- **TCP/MPTCP** in Linux — multipath TCP, kernel-level (MPTCP in kernel 5.6+).

### 5.3 The actual BalanSir question

The interesting question is **not** "how to migrate a raw socket" — it is
**"when to switch between DPI-bypass (B4) and VPN"** (§11). Migration
*within* a transport family is a solved problem (QUIC/WG). Migration *across*
policy paths (direct↔B4↔VPN) is a **policy decision**, which is exactly the
daemon's job.

### 5.4 When to switch — criteria to research further

- **Direct** is fine → never leave it. VPN is not the default.
- **B4 (DPI-bypass)** is a middle layer: if the direct path is being blocked,
  B4 is cheaper than a full VPN.
- **VPN** is the last resort for *reliability*, not the default for *everything*.
- **Fallback ladder:** direct → B4 → VPN, with per-flow policy overrides.

---

## 6. Warm-up / adaptive selection

### 6.1 Formalize the lifecycle

```text
cold → probe → warm → selected transport
                ↓
              degraded
                ↓
              fallback
```

### 6.2 What to measure

- **Latency** (RTT, TTFT), **loss**, **throughput**, **jitter**, **lifetime
  before drop** (corridor), **error rate**.

### 6.3 Probing budget

- Probing costs traffic and attention. Cap it: e.g. probe at most N KB / M
  seconds per transport, then commit to a selection for a hold-off window.
- **Avoid flapping:** a selection must be stable for a minimum dwell time
  before a lower-quality transport can replace it. Use hysteresis: switch only
  when the candidate is *meaningfully* better (e.g. 20–30%) and has been
  observed stable for K seconds.

### 6.4 Selection logic (direct/B4/VPN)

- **If direct is stable and faster than VPN → direct.** VPN is never the
  automatic default.
- **If VPN is substantially more reliable → VPN.**
- **If VPN unreachable → B4/direct fallback per policy.**
- Use **historical statistics** (per-destination, per-transport) rather than a
  single probe; a transport that was reliable this week beats a lucky 1-second
  probe.
- **RTC/time-based fallback:** if a known-good transport has been down for a
  long window, don't hammer it — fall back and re-probe on a long timer, not
  continuously.

### 6.5 After prolonged unavailability

- Exponential backoff on probes; mark the transport `degraded` (the daemon
  already has a health tier model — `HealthTier`, from the observability
  ADR). Reuse that, don't invent a parallel health model.

---

## 7. Adaptive MTU

### 7.1 The problem

MTU mismatch causes black-holes (fragmentation dropped, or ICMP-frag-needed
suppressed by DPI). Fixed MTU wastes capacity or breaks tunnels.

### 7.2 Algorithm to research

- **Discovery:** start from a conservative MTU; probe upward (like `ping
  -M do -s`).
- **Probing:** send size-increasing probes, detect success/failure.
- **Black-hole detection:** if a large packet fails but a small one succeeds,
  the size is the boundary; cache it per transport/destination.
- **Per-transport MTU:** WireGuard has its own MTU; QUIC has `max_udp_payload`
  and path MTU probing built in. Do not override what the transport already
  does.

### 7.3 Where should adaptive MTU live?

Three candidates:

| Home | Arguments |
|---|---|
| **BTP layer** | if BTP negotiates the transport, it can also negotiate MTU |
| **BalanSir datapath** | MTU is a per-flow property; the datapath already sees flows |
| **Transport driver** | WG/AWg/QUIC already manage their own MTU |

**Recommendation for research:** prefer the *transport driver* when the
transport manages MTU itself (QUIC, WG); use the **datapath** for TCP-based
transports where the OS stack needs explicit `MSS`/`DF` handling. Do not build
a BTP-wide MTU subsystem unless a specific transport needs it — otherwise it
is duplicating QUIC/WG's built-in PMTU.

---

## 8. Discovery and configuration

### 8.1 Research areas

- **Bootstrap** — first-contact without prior config.
- **Endpoint discovery** — how a node finds the peer's reachable addresses.
- **Signed configuration** — config updates must be authenticated.
- **Key rotation** — periodic, no session drops.
- **Capability advertisement** — what transports/features are available.
- **TTL / staleness** — configs expire; don't trust forever.
- **Offline operation** — the box enforces policy with *last-known-good*
  config when the server is unreachable.
- **RTC-based emergency fallback** — if config is missing/stale, use a
  hardcoded minimal safe fallback.

### 8.2 The critical requirement

> **The device must run for a long time with no discovery server.**

This means: policy and transport config are **signed artifacts with TTLs**,
cached locally, and refreshed opportunistically. A discovery server is an
optimization, not a dependency. This matches the existing strict config
parser (ADR-010): the config source is authoritative, the network is only a
delivery channel for signed updates.

### 8.3 Recommendation

- Config stays **TOML + signature** (the strict parser already exists).
- Discovery is a **delivery mechanism** for signed config, not a second truth
  (consistent with P3 decision: TOML authoritative, UCI/network renders).
- Emergency fallback = fail-closed empty action (ADR-019) or a signed minimal
  profile — product choice, already scoped.

---

## 9. Cryptography

### 9.1 Rule: don't invent crypto

Use standard primitives:

- **TLS 1.3** — for HTTP-based transports (ConnectRPC, HTTP/2+3).
- **Noise** — compact, handcrafted-channel friendly; WG uses a Noise-like
  handshake (Curve25519 + ChaCha20-Poly1305).
- **X25519 / Ed25519** — DH / signing.
- **AEAD** (AES-GCM or ChaCha20-Poly1305) — authenticated encryption.
- **Key rotation** — periodic re-key without dropping sessions.
- **Replay protection** — counters/nonce spaces.
- **Forward secrecy** — ephemeral DH (X25519), not static keys.

### 9.2 Explicit rejection

> **SHA / AES / Base64 / "register shifts" are NOT a way to make a protocol
> undetectable. Base64 is not encryption.**

This is a hard line: any design that tries to "obfuscate" traffic with
weak/non-crypto transforms is rejected. Fingerprint-resistance comes from
*looking like a real protocol* (§10), not from pseudo-crypto.

---

## 10. Traffic privacy / fingerprinting

### 10.1 What's researchable

Make a transport *look like ordinary HTTPS*:

- **TLS fingerprint** — ClientHello extensions, cipher ordering, ALPN
  (a real browser's TLS 1.3 ClientHello).
- **Packet sizes** — realistic record/segment sizes, not uniform.
- **Timing** — realistic inter-packet gaps, not a metronome.
- **Burst patterns** — application-like request/response bursts.
- **SNI/ALPN** — plausible values (but note SNI filtering exists).
- **HTTP/2 + HTTP/3 characteristics** — SETTINGS, HPACK/QPACK, stream usage.

### 10.2 Active probing

A censor with the client binary can actively fingerprint. No obfuscation
survives that forever; the goal is *raising the cost*, not *preventing
detection*.

### 10.3 The boundary

> **BTP must not promise "undetectability".**

The honest claim is: *reduces fingerprintability to approximately that of the
transport it mimics*. The product must not sell more than that. This is a
product-marketing constraint, not just a technical one.

---

## 11. Direct vs VPN vs B4 — the policy/selection logic

### 11.1 The architecture

```text
Application
     ↓
BalanSir Policy
     ↓
   ┌───────────────┐
   │ direct        │
   │ B4            │
   │ VPN           │
   │ fallback      │
   └───────────────┘
```

### 11.2 Research findings

- **VPN is not the default.** It is one candidate among three.
- Selection is a **policy decision** (daemon/planner), not a mechanism
  decision (executor). This keeps the A-series authority model intact: the
  daemon compiles "use path X for flow Y" into the same flow-criteria rules
  ADR-018 already produces; the executor just installs.
- **B4 is a distinct tier:** DPI-bypass is cheaper than a full tunnel. Use B4
  when direct is blocked but B4 works; escalate to VPN only when B4 also
  fails or policy demands reliability.
- The "direct after B4 is stable and faster → direct" rule means **downgrade
  is allowed**: a session can move VPN → B4 → direct as conditions improve.
  Selection is a continuous function of observed quality, not a one-way
  escalation.

### 11.3 Where this lands in BalanSir (future, not now)

`Action` already has `Route`, `Forward`, `Mark` variants and `DriverId`. The
path selection would compile to **flow rules with `Forward { driver }` /
`Mark` actions** (ADR-014's fwmark infrastructure), chosen by a planner that
reads transport health (HealthView already exists). No new datapath entity is
required by this research; it composes onto existing pieces.

---

## 12. Cascade / remote BalanSir

### 12.1 The two topologies

```text
phone/laptop
     ↓
mobile Internet
     ↓
remote BalanSir        ← acts as policy/security gateway
     ↓
home network
     ↓
Internet
```

and the inverse: **use the home BalanSir as the policy gateway** for remote
devices.

### 12.2 Research areas

- **Identity** — how a remote node authenticates to the home BalanSir.
- **Authentication** — mutual, key-based (Ed25519), with revocation.
- **Roaming** — remote node changes networks (cellular → WiFi); session
  survives (QUIC/WG migration covers transport).
- **NAT traversal** — home BalanSir is behind a router; need a rendezvous or
  inbound hole-punching (or an outbound-only model where the remote connects
  out and the home only *accepts*).
- **Security model** — the remote device is now inside the home's policy
  perimeter; policy must treat it as a distinct principal.

### 12.3 Key design decision

- **Model A: remote connects out to home (reverse)** — home is a server,
  remote is a client; NAT traversal trivial; home must be reachable.
- **Model B: rendezvous** — both sides connect to a discovery point; works
  behind NAT; adds a third party (which conflicts with offline-first §8 unless
  the rendezvous is optional).

**Recommendation for research:** Model A with an optional rendezvous, keeping
the offline-first principle: once a session key is established, no rendezvous
is needed.

---

## 13. Embedded deployment

### 13.1 Options

| Option | Fit |
|---|---|
| **Native Linux daemon** | current state; primary |
| **Buildroot package** | preferred embedded path (per DEPLOYMENT_RESEARCH) |
| **OpenWrt package** | deferred to a real target (per DEPLOYMENT_RESEARCH) |
| **Static binary** | good for appliances (already musl builds) |
| **Library/subsystem** | long-term goal, not now |
| **Container** | **explicitly not** the primary model (gate §11) |

### 13.2 The goal

> **BalanSir as a Linux networking subsystem, not a Docker application.**

This is achievable: it is already a set of small binaries + strict config +
systemd/capability hardening. The library/subsystem form (exposing policy as a
library + netlink/nft hooks) is a *future* refactor; the research conclusion is
that nothing in the current architecture prevents it, and nothing forces a
container model.

---

## 14. BTP-ML (research only)

### 14.1 What data is available

- Flow statistics (latency, loss, throughput, lifetime).
- Transport health history.
- Destination/domain history (DNS resolution, ADR-018's registry).
- Policy decisions and outcomes.

### 14.2 What could be optimized by heuristics/ML

- **Selection quality** — predict which transport will be reliable for a given
  destination/time.
- **Warm-up duration** — how long to probe before committing.
- **Corridor prediction** — is this destination likely to be volume-capped?

### 14.3 Where ML genuinely fits (embedded)

- Small, offline, quantized models only (sub-MB, single-core RISC-V).
- Heuristics first; ML only where a fixed rule is provably worse.
- **ML must never be a single point of failure.** The base system runs
  deterministically without BTP-ML; ML is an optional accelerator whose output
  is a *suggestion* to the selector, not an authority.

### 14.4 Recommendation

Do not design BTP-ML now. The correct order is: measure (instrument flows),
then heuristics (selection thresholds, dwell times), then — if data supports
it — a constrained ML model. The interface between "selector" and "ML advice"
should be a simple scored-candidate list, so ML can be added or removed
without touching the selection logic.

---

## 15. LibreQoS applicability

### 15.1 What LibreQoS contributes (architectural ideas, not code)

- **Flow classification** — identify flows by protocol/domain.
- **Queueing** — per-class queues.
- **Shaping** — rate limiting per class.
- **Fairness** — equitable bandwidth sharing.
- **Latency control** — AQM / buffer management (codel/fq_codel ideas).
- **Observability** — rich per-flow telemetry.
- **Policy-driven traffic management** — classes mapped from policy.

### 15.2 What belongs to BalanSir vs not

| LibreQoS idea | Belongs to BalanSir? | Why |
|---|---|---|
| Flow classification | yes | ADR-018 already classifies by flow criteria |
| Policy-driven classes | yes | the policy engine is the natural mapper |
| Queueing/shaping | **no (mechanism)** | belongs to the kernel (qdisc); BalanSir should *configure*, not implement |
| Latency control (fq_codel) | no (mechanism) | kernel qdisc; BalanSir configures it |
| Observability | yes | already has metrics/health tiers |
| Fairness | no | kernel/scheduler concern |

### 15.3 Conclusion

BalanSir should **express QoS policy** (class → action) and leave queueing/
shaping to the kernel qdisc layer it configures. Reusing ADR-018's flow
criteria as the classifier input is the natural bridge. LibreQoS is a source of
*ideas for the policy surface*, not a subsystem to import.

---

## 16. Architecture candidates

### A. No BTP

- **What:** keep the daemon + policy + executor; path selection stays manual
  (per-rule `Forward`/`Mark`). No new layer.
- **Pros:** zero complexity; everything already works; the A-series authority
  model is untouched.
- **Cons:** no automatic transport failover/migration; corridor mitigation and
  warm-up are manual.

### B. Thin control protocol

- **What:** a minimal control layer for discovery/config/negotiation (likely
  ConnectRPC over HTTP/2+3), **no new data transport** — the data path stays
  on existing mechanisms (direct/B4/VPN via policy rules).
- **Pros:** solves discovery, signed config, capability negotiation, stats
  collection — the *control* problems — without inventing a data protocol.
  Reuses TLS 1.3, QUIC migration, and the daemon's authority.
- **Cons:** doesn't by itself give per-flow migration; migration still needs
  the policy selector (§11).

### C. Full BTP

- **What:** a new protocol layer with its own session/path/transport entities
  and a new data transport.
- **Pros:** complete control.
- **Cons:** violates the hard constraint (new `BtpSession`/`BtpPath`/...),
  duplicates QUIC/WG migration, adds fingerprint surface, and re-creates the
  second-planner risk the A-series gates explicitly rejected. **Rejected.**

### D. Existing protocols + orchestration

- **What:** use QUIC (migration), TLS 1.3 (crypto), ConnectRPC or HTTP/2
  (control), and the existing VPN/DPI transports (data), orchestrated by the
  daemon's policy selector.
- **Pros:** every hard problem (migration, crypto, NAT, multiplexing) is
  already solved by a mainstream protocol; BalanSir adds only *selection
  policy*; authority stays in the daemon.
- **Cons:** requires the transport health view and selection logic (§6/§11) to
  be built; not free.

---

## 17. Final recommendation

**Adopt a phased path: C is rejected, A is the current baseline, B is the
first increment, D is the target.**

1. **Now (baseline = A):** nothing changes. BalanSir already composes
   `Forward`/`Mark` rules from policy (ADR-014/018). Path selection today is
   manual per-rule — acceptable.
2. **First increment (B):** when the control-plane problems actually appear
   (discovery, signed config, capability negotiation, stats), introduce a
   **thin control protocol based on ConnectRPC over HTTP/2+3 / TLS 1.3** —
   *as control, not data transport*. Signed config with TTLs, offline-first,
   reusing the strict TOML parser. This is the only new layer the research
   justifies, and it is a *control* layer, not a data path.
3. **Target (D):** add the **policy selector** (§6 warm-up + §11 direct/B4/VPN
   logic) that compiles to the existing flow rules. Migration comes free from
   the transports (QUIC/WG), not from a BalanSir protocol. This is the only
   part that touches the daemon, and it does so through the *existing* planner
   authority.
4. **Explicitly deferred:** full BTP protocol, BTP-ML, adaptive-MTU subsystem,
   and any new `Path`/`Session`/`Transport` entities — none are justified by
   this research. Measure corridor behavior (§4.4) before designing for 16 KB.

### Hard constraints honored

- No code, no new traits/crates, no `Btp*` entities in BalanSir.
- The daemon stays the sole authority; the executor stays a dumb mechanism;
  the planner stays the only planner.
- Cryptography is standard (TLS 1.3 / Noise / X25519 / AEAD); no
  pseudo-crypto, no "undetectability" promises.
- Offline-first, fail-closed on empty config (ADR-019), config-TTL-signed.
