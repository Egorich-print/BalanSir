# BalanSir Product Semantics — decisions for the owner (Gate list)

Status: decision-support (no code changed) · These are **product decisions**,
not engineering choices. The Production Readiness Gate classified each as
PRODUCT DECISION and deferred them to the owner. This document states the
current behavior, the options, and a recommendation per item. The owner picks;
implementation happens separately.

---

## P1. Empty config: fail-open vs fail-closed

**Current behavior (verified):** `DesiredConfig → DesiredState` is strict
(ADR-010). An empty config compiles to an empty desired state; reconcile then
installs nothing. The nft chain keeps whatever was there, and on a fresh boot
**there are no rules at all** — the kernel passes everything. The gate (v1 §12)
records this as honest but product-dependent.

**Why it matters on an appliance:** "no policy" on a firewall usually means
"permissive by accident". An operator who typo-deletes a config file must get
a predictable, safe outcome — and "safe" is a product call.

**Options:**

- **A. Fail-open (current):** empty desired = no rules = pass all. Predictable
  and matches the reconcile-not-replay model, but risky as a default on a
  gateway.
- **B. Fail-closed with an explicit last-resort rule:** empty desired compiles
  to a single terminal `drop` rule (or `drop` + an allowlist rule you opt
  into). Changes the planner contract: desired is never truly empty.
- **C. Fail-closed only in the executor:** the executor, when handed an empty
  inventory/desired over a config reload, installs a chain-level `drop` unless
  told otherwise. This moves the decision into the mechanism — closer to the
  kernel, but introduces an executor-side default (which the A-series gates
  deliberately avoided by keeping the executor non-authoritative).

**Recommendation:** **B** via a config flag
(`[policy] empty_config_action = "pass" | "drop"`, default `"pass"` to preserve
current behavior), implemented as a planner/compile concern so the executor
stays non-authoritative. Fail-open remains the default only because it is
today's honest behavior; the packaged appliance profiles would set `drop`.

**Owner decision needed:** default value + whether a packaged profile may
override it.

---

## P2. CLI / operator UID model

**Current behavior (verified):** IPC peer auth validates the peer UID against
`BALANSIR_ALLOWED_UIDS`, default `[0]` (root only), read from env at call time
(`ipc.rs::allowed_uids`). The daemon runs as `balansir` (systemd unit); the CLI
and the privileged control socket therefore only accept root by default. The
gate (v1 §5, §6) classifies the operator model as a product decision.

**Why it matters:** on an embedded appliance there is typically **one**
operator account (the admin). Forcing `sudo`/root for every `balansir-cli`
call is operationally awkward; but allowing any local user to reload firewall
policy is a security hole.

**Options:**

- **A. Root-only (current):** simplest, safest, matches single-admin routers.
- **B. Operator group:** introduce a `balansir` group; the daemon checks UID
  OR group membership. Ship `BALANSIR_ALLOWED_UIDS` examples in the packaged
  config. Requires reading the peer's groups over the socket (supplementary
  groups), a small IPC change.
- **C. Capability-based (Linux):** check `CAP_NET_ADMIN` on the peer instead
  of UID. Most flexible, but more complex and Linux-specific; the daemon is
  already Linux-oriented so this is viable.

**Recommendation:** **B** with a group `balansir-admin`, keeping root as an
implicit member. It preserves the single-admin default while letting a
packaged router grant a non-root operator the CLI. Implementation is a small
IPC-auth extension (peer group check) plus a `BALANSIR_ADMIN_GROUP` env var
alongside `BALANSIR_ALLOWED_UIDS`.

**Owner decision needed:** is a non-root operator in scope, or is root-only
the shipped model?

---

## P3. Production config source

**Current behavior (verified):** one TOML file (`config/balansir.toml`) parsed
strictly by `DesiredConfig` (ADR-010); `balansir-cli reload <path>` sends the
candidate; daemon reconciles transactionally. Profiles exist as
`config/profiles/*.toml`. The gate (v1 §6, §14) lists "production config
source" as ARCHITECTURAL/DEPLOYMENT on the gate list.

**Why it matters on an appliance:** a file an operator must edit by hand on
the box is error-prone and conflicts with Buildroot/OpenWrt packaging (UCI on
OpenWrt, config fragments in Buildroot). The A3 work (ADR-018) extended the
TOML schema with flow fields, so the config source now carries real policy
value.

**Options:**

- **A. Plain TOML file (current):** authoritative, strict, version-controlled.
  Good for Buildroot images; awkward for OpenWrt where UCI is the convention.
- **B. TOML stays authoritative; UCI/config-fragments render TOML:** the
  appliance's own config system generates the daemon's TOML on start. Daemon
  unchanged; packaging gains a renderer. Recommended in the deployment
  research doc (Section 4.3).
- **C. Daemon-side composite provider:** several TOML fragments merged with
  profile overrides (a `CompositeDesiredProvider` was anticipated in
  `provider.rs`). More moving parts; only worth it when profiles get complex.

**Recommendation:** **B**. Keep the strict TOML parser as the single source of
truth (ADR-010's atomic reject stays), and let each packaging path render TOML
from its own convention. Do not introduce a second parser in the daemon.

**Owner decision needed:** confirm TOML stays authoritative and UCI is a
renderer, not a second truth.

---

## P4. (Related) default action when the executor is unreachable

The gate (v1 §13) records: daemon startup with executor down → warn, stay up;
failed reconcile → rollback, no fabricated `Applied`. Behavior is "keep
last-applied kernel state, fail-closed on the delta". This is consistent and
needs **no decision**, but the packaged profile should state it explicitly so
operators do not misread a healthy-but-empty box.

---

## Decision table (for the owner)

| # | Item | Current | Recommendation | Blocks |
|---|------|---------|----------------|--------|
| P1 | Empty config | pass (fail-open) | flag, default pass, appliance profile `drop` | packaging |
| P2 | Operator UID | root-only `[0]` | `balansir-admin` group + env var | packaging, OpenWrt |
| P3 | Config source | TOML file | TOML authoritative; UCI renders TOML | OpenWrt |
| P4 | Executor down | keep-last, fail-closed on delta | document in profile (no change) | docs |
