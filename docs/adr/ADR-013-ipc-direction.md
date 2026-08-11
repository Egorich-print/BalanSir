# ADR-013: Privileged Boundary / IPC Direction (daemon → executor)

## Status
Proposed (M3.6.1 architecture spike — awaiting human approval before M3.7)

## Context

BalanSir has two processes (ADR-005): an unprivileged `balansir-daemon` that
owns policy/planning/orchestration, and a privileged `balansir-executor` that
owns privileged network mechanisms (nftables, netlink, fwmark/ip-rule later).

M3.5 + M3.6 built the pieces each side needs:

- `balansir-daemon` (`main.rs`): an IPC **server** that `accept()`s, then runs
  a respond-to-request loop (`handle_connection` → `recv` → `handle_message` →
  `send`). Its reconciliation path currently wires `PendingMechanismAdapter`
  (returns `Unsupported`) — it **never pushes** `AddRule`/`RemoveRule`/
  `FlushRules` to the executor.
- `balansir-executor` (`main.rs` + `service.rs`): an IPC **client** that
  `connect()`s to the daemon socket, sends an initial `HealthCheck`, then runs
  an M3.6 loop that `recv()`s commands and dispatches allowlisted ops to an
  nftables mechanism.

### The contradiction (verified)

The two integration tests encode **opposite** directions:

- `balansir-tests/src/ipc_integration.rs:test_full_pipeline` — **daemon → executor**:
  the "daemon" side sends `MsgType::AddRule`, the "executor" side receives and
  applies it.
- `balansir-tests/src/ipc_integration.rs:test_error_handling` — **executor → daemon**:
  the "executor" side sends `MsgType::StartDriver`, the daemon responds.

The production code is a third shape: the daemon is a **server that responds** to
whatever connects (health, driver ops), and the executor is a **client that
connects and (in M3.6) waits for commands**. There is no coherent,
production-wired command direction today.

ADR-005 is also stale: it shows `IpcMessage { version, msg_type, sequence,
payload }`, but the code has `correlation_id`; and it never states who binds the
socket or who initiates privileged operations.

M3.7 needs `PolicyEngine decision → daemon → executor → fwmark/ip-rule → kernel`.
That requires a real daemon→executor command channel. This ADR fixes the IPC
direction and failure model before M3.7, so the datapath is built on a coherent
boundary rather than on top of the current inverted roles.

## Decision

### Model A — executor is the privileged server; daemon is the commander/client

```
                 UNPRIVILEGED
┌──────────────────────────────────────┐
│              daemon                  │
│                                      │
│ Policy → Planner → Reconciler        │
│             │                        │
│             ▼                        │
│       ExecutorClient                 │
└─────────────┬────────────────────────┘
              │
              │ Unix socket (daemon → executor)
              │
              ▼
┌──────────────────────────────────────┐
│             executor                 │
│             PRIVILEGED               │
│                                      │
│ ExecutorServer                       │
│      │                               │
│      ├── nft                          │
│      ├── ip rule                      │
│      ├── ip route                     │
│      ├── fwmark                       │
│      └── future privileged ops       │
└──────────────────────────────────────┘
```

- **Who binds:** the executor binds a socket at a privileged path (e.g.
  `/run/balansir/executor.sock`), mode `0600`, owner root.
- **Who connects:** the daemon connects to the executor socket at startup (and
  reconnects on failure).
- **Direction:** the daemon sends **commands**; the executor **executes and
  responds**. The executor never initiates control, never plans, never reads
  desired state, never becomes a source of truth.

This matches the authority model the rest of the system already assumes:

```
DesiredState → Policy → ActualState → Plan → Operations → privileged execution
```

The daemon is the **only control-plane authority**; the executor is a **dumb
privileged mechanism executor**.

### Health/status

A **single bidirectional request/response protocol over one connection** is
preferred over a second channel. The daemon may query `HealthCheck`/`GetMetrics`/
status over the same socket it uses for commands. The executor never pushes
desired-state; it only answers queries and reports operation results.

## Why A over the alternatives

| | A (executor server) | B (second channel) | C (status quo) |
|---|---|---|---|
| Matches real authority flow | ✅ daemon commands | ⚠️ duplicates channel | ❌ inverted/undefined |
| Executor = dumb mechanism | ✅ | ✅ | ❌ (executor is client that must "ask") |
| Second control-plane risk | low | medium | **high** (ambiguous who commands) |
| Complexity now | medium (one socket, one direction) | high (two channels, two lifecycles) | none (but broken) |
| Restart/reconnect | one reconnect path | two reconnect paths | unclear |
| Integration tests | coherent (daemon→executor) | mixed | contradictory today |
| Future: fwmark/ip-rule/datapath/driver-ops | natural | extra hop | needs reversal anyway |
| Cascade VPN / remote / BTP later | daemon remains sole authority | ok | must redesign |

Model B is rejected: it keeps the current (inverted) executor-client shape and
adds a *second* daemon→executor channel, doubling connection/lifecycle/restart
complexity and leaving the ambiguity of the existing client channel. It does not
resolve the "who commands" question — it papers over it.

Model C is the current state: the executor connects to the daemon, but nothing
commands anything coherently; the M3.6 loop sits on a client socket that nothing
production writes to. It cannot support M3.7 without reversal, so it is not a
viable end state.

**A is selected**: it makes the executor's privileged nature and the daemon's
authority explicit, is the smallest coherent change (reverse bind/connect, keep
one request/response protocol), and prevents a second control plane.

## Consequences (the 15 decision points)

1. **Who binds:** executor binds `/run/balansir/executor.sock` (root, `0600`).
   Daemon does not bind a privileged-executor socket.
2. **Who connects:** daemon connects (unprivileged) to the executor socket;
   reconnects with backoff on failure.
3. **Connection lifetime:** one persistent command connection per daemon↔executor
   pair, with reconnect on drop; no per-command connect.
4. **Authentication:** both sides still validate peer credentials
   (`SO_PEERCRED` on Linux / `getpeereid` elsewhere) — the daemon verifies the
   executor's UID, the executor verifies the daemon's UID. Existing `allowed_uids`
   mechanism is reused.
5. **Request/response:** reuse `IpcMessage`/`MsgType`/`correlation_id`
   (postcard). Commands are requests; executor returns `ResponseOk`/
   `ResponseError`/`ResponseData`.
6. **Asynchronous command:** not now. Single-connection request/response,
   serialized by the daemon (the daemon's reconcile already serializes). Async
   streaming is deferred until a concrete need exists.
7. **Command ID:** reuse `correlation_id` (monotonic per connection) as the
   command identity for matching responses.
8. **Acknowledgement:** executor responds per command with an explicit
   `Response*`; the daemon awaits it before committing (preserves reconcile
   transaction semantics).
9. **Executor restart:** daemon detects dropped connection, reconnects, and
   re-issues the current desired reconcile (or marks mechanism unavailable) —
   handled by the existing reconcile/rollback path.
10. **Daemon restart:** executor keeps serving; on daemon reconnect it simply
    accepts the new command session. No executor-side state is the authority.
11. **Lost connection:** in-flight command fails with an explicit error; daemon
    rolls back that reconcile via the existing `Snapshot`/`Rollback` path and
    reconnects.
12. **Replay/idempotency:** reconcile is already idempotent at the planner level
    (unchanged desired → no-op). Operation-level idempotency (re-applying the
    same rule) is the executor's `AlreadyApplied` path, which already exists.
    `correlation_id` prevents cross-command response confusion.
13. **Transaction boundary:** the daemon's reconcile FSM remains the single
    transaction boundary (ADR-010/011). The executor's per-command response is
    the mechanism-level ack; commit happens in the daemon.
14. **Rollback semantics:** unchanged — the daemon owns rollback via
    `SnapshotStore`/`Rollback` (existing). The executor only applies/removes
    what it is told.
15. **Executor never a source of truth:** the executor holds no desired state,
    no policy, no planner; it executes only the operations the daemon sends. Its
    only "state" is the current mechanism application, reported on query.

## Explicit non-goals (M3.6.1)

- No BTP / datapath / fwmark / ML / remote / cascade design.
- No new protocol framing beyond reversing the bind/connect direction and
  documenting the failure model.
- No executor-initiated control.

## Migration path (for M3.7+, not implemented here)

1. Executor binds its own socket; daemon connects (role reversal in
   `main.rs`/`service.rs` + integration tests).
2. Daemon's reconcile path replaces `PendingMechanismAdapter` with an
   `ExecutorClient` adapter that sends `AddRule/RemoveRule/FlushRules` and maps
   the typed `ActionResult` back.
3. M3.7 fwmark/ip-rule mechanism lands inside the executor, behind the same
   allowlist.

## Verification (to run on approval)

- Host: `cargo test --workspace`, clippy, fmt.
- Linux: x86_64 + aarch64 + riscv64/musl CI.
- Integration: reversed-direction test (daemon sends `AddRule`, executor applies,
  response matches `correlation_id`).

## Decision record

The spike found the M3.7 blocker (no production daemon→executor command channel;
inverted/contradictory roles). Model A resolves it by making the executor the
privileged server and the daemon the sole commander, keeping one
request/response protocol. Awaiting human approval before M3.7 datapath
implementation.
