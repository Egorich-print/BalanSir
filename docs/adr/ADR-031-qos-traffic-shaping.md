# ADR-031: QoS / Traffic shaping (HTB + fq_codel)

Status: accepted (2026-08-14)

## Context
BalanSir must shape traffic (LibreQoS-inspired) as a first-class, Rust-native
mechanism — not an external script or decorative stub. The daemon is the
single planning authority; the executor is the privileged mechanism.

## Decision
- New `QosPlan`/`QosClass`/`QosState` types in `balansir-common`; `DesiredState`
  gains an optional `qos` field (`#[serde(default)]` for JSON reload).
- Executor owns the **applied** shaping state (non-authority, like the rule
  inventory). `TcBackend` renders an HTB root qdisc + per-class fq_codel leaves
  via the `tc` CLI, with identifier/rate validation and idempotent apply/clear.
- IPC gains `ApplyQos`/`ClearQos`/`GetQosState`; `Executor`/`ExecutorAdapter`
  gain matching methods.
- `Reconciler::reconcile_atomic` converges desired QoS plans independently of
  nft rule reconciliation, so a shaping failure never blocks rules.
- WebUI reads desired-vs-applied via `GET /api/qos/status`.

## Consequences
- No shell interpolation or arbitrary user commands; `tc` args are validated.
- Applied state is reported (not assumed), so the daemon reconciles drift.
- Interface defaults: HTB default rate/ceil + optional per-class buckets.
