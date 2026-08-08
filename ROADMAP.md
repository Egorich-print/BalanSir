# BalanSir — Roadmap

> Дата: 2026-08-07 | Источник: `ARCHITECTURE_AUDIT.md` + `TECH_DEBT.md`
> Принцип: маленькие pack'и → проверка (`cargo test/clippy/fmt`) → ADR → коммит.

---

## Milestone 0 — Аудит (DONE ✅)

Документы созданы: `PROJECT_STATE.md`, `ARCHITECTURE_AUDIT.md`, `TECH_DEBT.md`,
`ROADMAP.md` (этот файл).

---

## Milestone 1 — Security & Runtime foundation (приоритет)

**Цель:** убрать 6 Critical + ключевые High security-находки, не меняя архитектуру.

| # | Задача | Файлы | Связанный tech-debt |
|---|--------|-------|---------------------|
| 1.1 | Сокет daemon → `/run/balansir/daemon.sock`, `set_permissions(0o600)`, `bind_unlink_safe` | `daemon/src/main.rs`, `executor/src/main.rs` | C1, C6, M15 |
| 1.2 | Секреты драйверов → `/run/balansir/<driver>-<id>.json` mode 0600 + wipe на Drop | `xray.rs`, `hysteria.rs`, `b4.rs` | C2, M8 |
| 1.3 | Hardening executor systemd unit (drop root, ambient caps, NoNewPrivileges, ProtectSystem, SystemCallFilter, CapabilityBoundingSet) + стартовый `getuid()==0` assert | `deploy/systemd/balansir-executor.service`, `executor/src/main.rs` | C3, M14 |
| 1.4 | IPC mutual auth: add `validate_peer_cred` на executor side; конфиг `ALLOWED_UIDS` | `ipc.rs`, `executor/src/main.rs` | C4, H7 |
| 1.5 | `FileStateStore::save` fsync tmp + parent dir; key-allowlist `^[A-Za-z0-9_-]{1,32}$`; DirBuilder mode 0700; journal len cap | `state/file.rs` | H8, H9, M6, M12 |
| 1.6 | Абсолютные пути бинарников (`which` на старте) для `ip`/`nft`/`pgrep`/`pkill` | `wireguard.rs`, `nftables.rs`, `xray.rs`, `hysteria.rs`, `b4.rs` | H10 |
| 1.7 | API bind → default `127.0.0.1` + admin-token middleware + unix-socket option | `api/src/lib.rs`, `handlers.rs` | H11 |
| 1.8 | `cargo-audit`/`cargo-deny` в CI | `.github/workflows/ci.yml` | L11 |

**ADR:** `ADR-006-runtime-paths-and-secrets.md` (сокет/state/secrets в `/run/balansir/`, права).
**Проверка:** `cargo test --workspace`, `cargo clippy --workspace`, `cargo fmt --check`,
интеграционный smoke под `/run/balansir/` (если root).

---

## Milestone 2 — Architecture hardening (Этап 2 из задания)

**Цель:** укрепить границы модулей; подключить API к control plane; реальный Rollback;
policy ↔ health. Подготовка v0.5+.

| # | Задача | Файлы | Debt |
|---|--------|-------|------|
| 2.1 | Перенести `Rollback` trait + `NoopRollback` из `coordinator.rs` в `traits.rs` | `control/src/coordinator.rs`, `traits.rs`, `lib.rs` | L5 |
| 2.2 | Убрать re-export common-символов из `reconciliation/mod.rs`; обновить импортеры | `daemon/src/reconciliation/mod.rs`, `tests/stress.rs` | L4 |
| 2.3 | Разбить `reconciliation/mod.rs` на `reconciler.rs` / `adapters.rs` (`DaemonActualStore`+`DaemonExecutorAdapter`+`DaemonRollback`) / `sinks.rs` / `dummy.rs`; `-`-arm для `CreateDriver`/`DropDriver` логировать unsupported | `daemon/src/reconciliation/*` | H2 |
| 2.4 | Реальный `Rollback` через executor IPC undo (or revert-plan) | `reconciliation`, `executor` | H3 |
| 2.5 | API → `balansir-control`: `Arc<dyn DesiredProvider>` + `Coordinator::reconcile(ApiRequest)`; удалить stub `ReconcilerHandle`; реализовать 5 TODO-handlers | `api/src/*` | H1 |
| 2.6 | Policy engine: `evaluate(ctx, &health_view)`; на `Forward{driver}` с `Unhealthy` → `rule.fallback`; default-deny опция | `policy/mod.rs`, `types.rs` | H4, M16 |
| 2.7 | typed policy errors (`PolicyError`); убрать `Result<_, String>` в `policy/rules.rs`, `profile.rs`, `reconciliation/mod.rs` | по файлам | M3 |
| 2.8 | `secrecy::SecretString`/`zeroize` + `#[serde(skip_serializing)]` для секретов; redaction в `Debug` | `wireguard.rs`, `amneziawg.rs`, `xray.rs`, `hysteria.rs` | M4 |
| 2.9 | Структурированный `NftRuleSpec` вместо `add_rule(&str)` | `executor/src/nftables.rs` | C5, M5 |
| 2.10 | Решить M9 (TOML `Forward{driver}` → `DriverId` по имени через registry/enum-map) | `policy/rules.rs`, `types.rs` | M9 |

**ADR-007** `API-control-plane-port.md` (API зависит только от `balansir-control`).
**ADR-008** `policy-health-fallback.md` (failover через `rule.fallback` + health).
**ADR-009** `typed-errors.md` (typed PolicyError/ProfileError/ReconciliationError).
**Статус:** ✅ выполнено (2.1–2.10), коммиты `0651834..959fe81`.
**Проверка:** test+clippy+fmt после каждого шага.

---

## Milestone 3 — Feature delivery (Этап 3 из задания)

| # | Фича | Декомпозиция |
|---|------|--------------|
| 3.1 | **Hot Reload** `/reload` без рестарта daemon | `DaemonDesiredProvider` следит за `DesiredState`源的 (file watcher → EventBus `ConfigReload`); Coordinator `ReconcileReason::ConfigReload`; API `/reload`. |
| 3.2 | **Runtime Driver Lifecycle** | ✅ `driver/lifecycle.rs`: state machine `Absent→Initializing→Active / Replacing / Stopping / Degraded/Failed→Recovering`; two-phase atomic reconcile (stage→commit, failure keeps old runtime — failure ≠ removal); no-op on unchanged fingerprint; recovery without touching desired; secrets wiped on slot drop (M2.8); `MsgType::{Start,Stop,Restart}Driver` wired в `daemon/main.rs` через `DriverLifecycleManager` + `NotYetWiredFactory` (real configs в M3.4/M3.5); structured `DriverLifecycleEvent` data for M3.3. ADR-011. |
| 3.3 | **Observability** (расширение) | ✅ Унифицировать metrics через `prometheus-client` (`common/src/metrics.rs` — `balansir_drivers{tier="…"}` gauge-family + `balansir_driver_lifecycle_transitions_total`); health tiers `Healthy→Degraded→Failing→Disabled` в `ControlEvent::DriverHealthTierChanged { id, tier }` + `balansir_common::HealthTier`; orchestration layer `driver/health.rs` (`TierTracker`, only-on-change emission) — lifecycle manager свободен от metrics/event deps; `Event::ComponentHealthChanged` reused → `BoundedEventBus` → `/events/stream`; `/metrics` + `GetMetrics` (`response_data`). **OTel deferred (ADR-012)** — добавляется как optional `tracing` layer, когда появится реальный collector, без изменения контракта. ADR-012. |
| 3.4 | **Plan Engine Refactor** | `Current State → Desired State → Execution Plan` интерфейсный split; в `balansir-control` уже есть `Planner` порт + `BasicPlanner` + `StateDiff::build` в `common/src/diff.rs`; добавить dry-run/explain endpoint (`plan.rs`+`executor.rs` семантика). |
| 3.5 | **Async drivers** | `tokio::process::Command` + `tokio::fs` во всех `ComponentDriver` (H5); хранить `Child` (M8). |

**ADR-009** `hot-reload-and-event-bus.md`, **ADR-010** `driver-lifecycle-manager.md`,
**ADR-011** `plan-engine-dry-run-explain.md`.

---

## Критерии завершения (из задания)

- **Архитектура:** policy/механизм разделены (✅ фундамент есть); driver system
  расширяема (✅ trait+enum); daemon/executor безопасна (после M1+M2.4).
- **Код:** чистый Rust, `Result` вместо panic, typed errors, tracing, api-docs.
- **Функциональность:** policy eval ✅; simulation/dry-run (M3.4); explain ✅;
  drivers load/stop/replace (M3.2); reload (M3.1); observability (M3.3).
- **Документация:** README.ru ✅; ADR-000..005 ✅ + ADR-006..011 (M1–M3);
  examples (добавить `examples/`).

---

## Принцип выполнения

1. Анализ конкретной задачи → минимальный diff pack.
2. Реализация → `cargo test --workspace` (green).
3. `cargo clippy --workspace --all-targets` (0 warnings), `cargo fmt --check`.
4. ADR для значимого решения; обновление `TECH_DEBT.md` / `STATUS.md`.
5. Коммит с conventional-commit сообщением; push на `origin/main` по запросу.

Рабочий cadence — по 1–3 задачи milestone за итерацию, без массовых переписываний.
