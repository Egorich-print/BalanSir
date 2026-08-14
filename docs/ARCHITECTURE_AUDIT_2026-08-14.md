# BalanSir — Architecture & Integration Audit (2026-08-14)

> Mission: turn the fast-assembled feature set into a coherent, safe, testable
> system where Direct/B4/Xray/DNS/QoS/Tailscale/Policy/Executor/WebUI work
> through unified models of state, health, reconciliation and observability.
>
> Scope: software/architecture audit + integration fixes. No new deployment
> mission, no Buildroot packaging, no production image rebuild.

---

## 1. State ownership model (as implemented)

```
Desired  → authoritative configuration (policy store / TOML / API intent)
Actual   → observed kernel/runtime state (executor readback, driver probes)
Health   → measured runtime condition   (common::path_health::PathHealth)
Metrics  → derived observability        (unified metrics registry)
Events   → immutable observations       (unified broadcast event stream)
Snapshot → single cached projection     (SharedSubsystemSnapshot, /subsystems)
```

One fact is never stored twice as an independent truth:

| Fact | Single owner | Exposed via |
|---|---|---|
| Path health | `PathHealth` per path (daemon managers) | `PathHealthView` in subsystem snapshot |
| Xray active endpoint | `XrayManager.active` | `xray` snapshot |
| QoS applied state | QoS manager readback | `qos` snapshot |
| DNS registry | `DnsRegistry` (shared by flow compiler + forwarder) | policy compile output |
| Reconciliation outcome | reconciler (shared metrics) | metrics + events |
| B4 decisions | B4 engine (DNS status feed) | `b4` snapshot |

`Desired`, `Actual`, `Health` and `Metrics` are **never** mixed: managers
project the shared `PathHealth` state into UI-compatible strings, they do not
recompute health.

## 2. What was found

### 2.1 Dead code / stale architecture
- `crates/balansir-daemon/src/health.rs` (`PathHealthTracker` + ping probes)
  was **never wired into any decision path** — a dead prototype that duplicated
  the unified `balansir-common::path_health` model (which *is* wired: Xray
  failover, B4 projection). Removed.
- `docs/adr/ADR-032` described the dead tracker as the design; marked
  superseded and replaced with a truthful description of the landed model.
- B4 driver tests used `DriverId::Hysteria` as the B4 id; fixed to
  `DriverId::B4`.

### 2.2 DNS plane (`dns_plane.rs`) — hostile-input correctness
- Parser rewritten from a high-bit match to byte-level checks. The old match
  arm `0 =>` also matched valid label lengths (e.g. `3 & 0xC0 == 0`), which
  broke **every** normal name decode (`decode_name` returned `BadLabel`).
- Compression pointer target, `visited` set, `MAX_POINTER_JUMPS`,
  `MAX_NAME_LEN`, reserved-label rejection, TTL clamping to
  `MAX_OBSERVED_TTL`, truncation/`TC`, NXDOMAIN/SERVFAIL/REFUSED exclusion,
  `qr` bit guard — all covered by unit tests including fuzz-style hostile
  inputs (`hostile_inputs_never_panic`, pointer-loop, out-of-range pointer,
  oversized label, truncated record/response).
- DNS registry is TTL-aware: observations expire, authoritative inserts never
  expire; the DNS forwarder ingests observed responses into the **shared**
  registry so `dns` policy rules and B4 DNS observation see the same facts.

### 2.3 Xray manager — failover/pin consistency
- **Switch loop (real bug):** `health_and_failover` fails over away from a
  failing endpoint, but the next `ensure_running` pass pulled straight back to
  a `pinned` failing endpoint — two-loop alternation. Now failover **consumes
  the operator pin when it names the failing endpoint**; a pin on a healthy
  endpoint is preserved.
- `switch_to` / `switch_to_index` were two divergent copies of the same
  semantics; unified into one implementation.
- Latency probes serialized N×3s inside the health loop; now concurrent
  `tokio::spawn` probes (RPi 3B+ friendly).
- Endpoint driver factory is injectable (`from_toml_with_starter`) so failover
  is testable without an xray binary. Added deterministic regression tests:
  pin consumption + no switch loop, and pin preservation for a healthy target.

### 2.4 API honesty
- `/health` returned hardcoded `"version": "0.1.0"`; now
  `CARGO_PKG_VERSION`.
- `/drivers/:id/restart` claimed `"Restart requested"` while the API control
  plane never restarts drivers (restart lives in the privileged IPC
  lifecycle). The endpoint now rejects honestly instead of lying.

### 2.5 Privilege separation
- `balansir-daemon` runs unprivileged and now binds the DNS forwarder socket
  (default `127.0.0.1:53`) via `CAP_NET_BIND_SERVICE` scoped in the systemd
  unit (`AmbientCapabilities` + `CapabilityBoundingSet`, `NoNewPrivileges`).
  No privileged fallback was added to the daemon; privileged operations remain
  exclusively in the executor over authenticated IPC.

### 2.6 Metrics/observability consistency
- Reconciler and API server now share the same metrics registry instance, so
  counters emitted by the reconcile loop and served by `/metrics` come from
  one source.
- The dead `health` module's metrics were removed with the module.

## 3. Honest capability classification

| Subsystem | Status | Notes |
|---|---|---|
| Path Health (`common::path_health`) | implemented | unified hysteresis/EMA/cooldown model; drives Xray failover; projected by B4 |
| DNS plane (`dns_plane.rs`) | implemented | hostile-input tested; **no TCP fallback** — declared scope limitation |
| DNS registry (TTL) | implemented | shared desired-state input for policy + B4 |
| Xray integration | implemented | failover, rotation, pin semantics, config validation |
| B4 | minimal working adaptation | route/MTU adaptation scope, **not** a packet-level datapath |
| QoS (netlink) | implemented | Linux-target; apply/readback/drift tested in `qdisc` unit tests |
| Tailscale | integration scaffold | command invocation + status parsing; not an admin console |
| WebUI | client of backend truth | renders snapshot projections; no duplicated decision logic |
| TCP DNS fallback | research/future | requires a forwarder-level resolver change; no correctness hole found for current policy/B4 feed |

## 4. Verification

```text
cargo fmt --check            → clean
cargo check --workspace      → clean
cargo test --workspace       → all green (14 api + 57 common + 4 stress +
                                18 control + 181 daemon + 1 control_plane
                                + 5 stress + 49 executor + 5 image + 5 ipc
                                + 4 root-only netns ignored)
cargo clippy --workspace --all-targets -- -D warnings → clean
```

Root-only netns tests (4, `--ignored`) and the QEMU image boot test
(`deploy/buildroot/qemu-test.sh`) require privileged/`qemu-system-aarch64`
environments and are documented as such; they are unchanged.

## 5. Known limitations (explicit scope)

- **B4** is a minimal route/MTU adaptation, not a packet-level bypass. This is
  intentional and documented; nothing in this mission changes that boundary.
- **DNS TCP fallback** for truncated responses is not implemented. The parser
  safely rejects `TC` responses and the forwarder passes the message through
  unchanged; no correctness hole exists for the current policy/B4 feed.
- **Tailscale** remains an integration scaffold (status + lifecycle via
  structured invocation); BalanSir is explicitly not a Tailscale admin
  console.
- **Xray failover health** is driven by the local SOCKS inbound liveness
  probe (consistent with the pre-existing design); endpoint-latency probing is
  observability-only and does not influence selection.
- QEMU and root-only tests must run on a host with QEMU/privileges.
