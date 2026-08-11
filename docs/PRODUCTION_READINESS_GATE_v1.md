# BalanSir Production Readiness Gate v1

Status: host verification · Date: M3.8 committed (`7e22a9e`) · No code changed
Purpose: short hostile check of the M3.4–M3.8 foundation. Every finding is
classified only — no fixes applied.

Classification legend:

- **BUG** — concrete defect in current code (would fail or misbehave in normal use).
- **ARCHITECTURAL DECISION** — the code behaves as designed; changing it requires an architecture decision.
- **PRODUCT DECISION** — semantics are not an engineering choice; a product owner must choose.
- **DEFERRED** — intentionally out of scope for this milestone, tracked for later.

---

## 1. Real daemon → executor → nft path

**Verified (FACT):**
- daemon owns `Reconciler` → `ExecutorClient` (connects to `executor.sock`) →
  sends `AddRule`/`RemoveRule`/`FlushRules` over postcard IPC →
  executor (server, root) `NftablesExecutor` maps to `NftablesBackend`
  (`nft add rule ... meta mark set N ... comment "balansir:<id>"`) → kernel.
- `DesiredRule.id` flows as `ActionRequest.trace.policy_id` so removal is
  handle-based (`nft -a list chain` → `# handle N`).

**Finding:**
- **DEFERRED (scope):** the datapath is **chain-level verdict**, not per-flow:
  `apply_rule` sends all-zero flow fields because `DesiredRule` has no matcher.
  This is the known flow-level-policy fork (Gate Step 2, A3), not a BUG.

---

## 2. Rollback

**Verified (FACT):** `DaemonRollback::rollback` reverts kernel rules added
beyond the snapshot (by id), then restores in-memory `ActualState`. Partial
failure → coordinator rollback. Covered by
`rollback_reverts_added_rules_and_restores_snapshot` (test).

**Findings:**
- **ARCHITECTURAL DECISION:** rollback correctness depends on `ActualState`
  being accurate. When it is, rollback is correct.
- **ARCHITECTURAL DECISION (Gate A2):** if `ActualState` diverged (see §3),
  rollback cannot see an orphan it doesn't know about.

---

## 3. Executor loss during an operation (orphan window)

**Verified (FACT):** ack-gap scenario exists:
`daemon AddRule → executor nft add → [ACK lost] → executor dies`.
Daemon `ActualState` = "absent"; kernel = "present". Reconcile recomputes
`Desired − Actual` and cannot see the orphan.

**Finding:**
- **ARCHITECTURAL DECISION (most important, Gate A2):** closing this needs
  **executor startup inventory + daemon reconcile** (executor reports the netns
  rule set; daemon reconciles against Desired). Executor stays non-authority.
  Working hypothesis, not yet a decision.

---

## 4. Restart daemon / executor

**Verified (FACT):**
- daemon restart → reconnects `ExecutorClient`, re-runs initial reconcile
  (empty desired → no-op; real desired via later `reload`).
- executor restart → daemon reconnect + recompute `Desired − Actual`
  (ADR-013). Kernel rules persist across executor restart (they are kernel
  state).

**Finding:**
- **DEFERRED / ARCHITECTURAL DECISION (A2):** reconnection convergence is only
  correct for what `ActualState` knows; orphan convergence is the A2 item.

---

## 5. IPC authentication

**Verified (FACT):**
- Linux: `SO_PEERCRED`/`ucred`; non-Linux: `getpeereid`. Both sides validate
  (`IpcServerConnection::accept` on executor + daemon control socket;
  `IpcClientConnection::connect`). `BALANSIR_ALLOWED_UIDS` default `[0]`.
- daemon.sock = unprivileged control (CLI, legacy driver ops);
  executor.sock = privileged command channel (daemon→executor).

**Findings:**
- **PRODUCT DECISION:** default allowlist `[0]` (root-only) means operators must
  either run the CLI/executor as root or configure `BALANSIR_ALLOWED_UIDS`.
  Acceptable for a privileged network appliance; product decides the
  operational user model.
- **ARCHITECTURAL DECISION:** `allowed_uids()` reads an env var at call time —
  no daemon reload of the allowlist. Fine for v1; a runtime-authz config would
  be a later decision.

---

## 6. CLI (`balansir-cli`)

**Verified (FACT):** `status / plan / explain / desired / actual / reload
<config.toml>` over daemon.sock. `reload` parses TOML strictly (ADR-010),
sends the candidate `DesiredState`, daemon reconciles transactionally
(`Reconciler::reload`).

**Findings:**
- **PRODUCT DECISION:** CLI must run as an allowed UID (default root). No
  separate operator-credential model yet.
- **DEFERRED:** no CLI completion/help beyond usage line; acceptable for v1.

---

## 7. IPv4

**Verified (FACT):** `ActionRequest.src_ip/dst_ip` are `[u8;4]`; nft table is
`inet` (dual-stack) but rules emit `ip saddr` (IPv4). IPv6 is unrepresentable,
not hidden in `Unsupported`.

**Finding:**
- **ARCHITECTURAL DECISION (Gate A4):** move to `std::net::IpAddr`/`Ipv4Addr`/
  `Ipv6Addr`, or keep IPv4-only as an explicit contract. Not a BUG.

---

## 8. Real nft rules

**Verified (FACT):** `NftablesBackend` shells to `nft` with typed positional
args (no shell interpolation); mark (`meta mark set N`) and comment tagging
render correctly (unit-tested); handle-based removal unit-tested; privileged
netns test (`#[ignore]`, root) drives the production backend.

**Findings:**
- **DEFERRED (environment):** real kernel enforcement is **proved by
  privileged environment only** (`sudo cargo test -p balansir-tests -- --ignored`).
  CI has no CAP_NET_ADMIN. This is honest (never fabricated).
- **ARCHITECTURAL DECISION:** no `ip rule`/routing-table wiring yet —
  `Route`/`Forward` are intentionally unsupported (Gate Step 4).

---

## 9. Policy bypass

**Verified (FACT):** `PolicyEngine`/`PacketContext` have **zero production
callers** (library/test only). No datapath calls `evaluate`; no second planner;
executor has no policy logic. `ALLOW` is a plan action, not a bypass.

**Finding:**
- **ARCHITECTURAL DECISION (Gate A3):** because there is no per-flow packet
  path yet, "enforcement" is kernel-verdict-level. No bypass exists today, and
  none is possible (nothing can skip the engine). The flow-level compilation
  design (DNS/conn metadata → compiled nft rules) is the A3 decision.

---

## 10. Linux x86_64 / aarch64 / riscv64

**Verified (FACT):** CI builds x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu,
riscv64gc-unknown-linux-musl — all green. `SO_PEERCRED` used on Linux; musl
supported. `M3.7` commit series kept all three targets green.

**Finding:**
- **None (gate passes).**

---

## 11. Embedded build story

**Verified (FACT):** release profile is embedded-oriented (size-z, LTO,
panic=abort); `tokio::current_thread`; systemd units exist; `riscv64`/musl
target in CI; `.cargo/config.toml` has cross linker config.

**Findings:**
- **DEFERRED (deployment research, Gate Step 5):** Buildroot/OpenWRT package
  integration and any Vivanta embedding are research items, not current code
  gaps. Docker/Podman are not the default model.

---

## 12. Empty / broken config

**Verified (FACT):** `DesiredConfig → DesiredState` is a strict `TryFrom`
(ADR-010): unknown action/driver, malformed rule, or bad CIDR aborts the whole
reload. Empty config → empty desired → no-op reconcile (no enforcement rules).

**Findings:**
- **ARCHITECTURAL DECISION:** empty desired state installs nothing — correct
  and honest.
- **PRODUCT DECISION:** what an *empty* config should mean operationally
  (fail-open vs fail-closed on the whole chain) is a product choice (Gate list
  item "fail-open/fail-closed").

---

## 13. Executor unavailable

**Verified (FACT):** daemon startup reconcile with executor down → `warn`
(not fatal); daemon stays up serving control queries. `ExecutorClient::request`
fails → `apply_rule`/`RemovePolicy` fail → reconcile rolls back. No fabricated
`Applied`.

**Finding:**
- **ARCHITECTURAL DECISION:** behavior is "keep last-applied kernel state,
  fail-closed on the delta" — consistent with reconcile-not-replay. The
  product-level fail-open/closed profile is a separate decision.

---

## 14. Empty / broken config — CLI path

**Verified (FACT):** `balansir-cli reload` uses `DesiredConfig::from_file` +
`DesiredState::try_from` — strict, aborts on malformed input, sends nothing on
error.

**Finding:**
- **None.**

---

## Verdict

**Can BalanSir M3.4–M3.8 be considered an honest minimal production
foundation, knowing its limits? — YES.**

The daemon→executor→nft path, rollback, IPC auth, CLI, config strictness, and
Linux builds are real and correct within their defined scope. No BUGs were
found that break normal operation. The limits are architectural decisions that
are correctly deferred or require a human gate:

| Area | Classification | Gate |
|---|---|---|
| Flow-level policy (chain-level today) | ARCHITECTURAL DECISION | A3 |
| Rule identity / idempotency (`same id ≠ same rule`) | ARCHITECTURAL DECISION | A1 |
| Orphaned kernel state (ack-gap) | ARCHITECTURAL DECISION (most important) | A2 |
| IPv6 | ARCHITECTURAL DECISION | A4 |
| Route/Forward | ARCHITECTURAL DECISION (intentionally unsupported) | Step 4 |
| Fail-open/fail-closed | PRODUCT DECISION | Gate list |
| Production config source | ARCHITECTURAL/DEPLOYMENT | Gate list |
| CLI/operator UID model | PRODUCT DECISION | Gate list |
| Real nft privileged proof | DEFERRED (environment) | runner |
| Buildroot/OpenWRT/Vivanta | DEFERRED (research) | Step 5 |
| Per-flow enforcement in CI | DEFERRED (no CAP_NET_ADMIN) | runner |

**Baseline `BalanSir M3.8 Foundation` is honest.** Further development should
begin with the Architecture Gate (A1–A4 + deployment + product semantics), then
BTP Architecture Research — not with another coding milestone.
