# BalanSir — Architecture Audit

> Дата: 2026-08-07 | Режим: read-only аудит кода | Объект: `crates/` (52 файла)

---

## 1. Dependency graph

```
                      +---------------------+
                      |  balansir-common    |   (base layer; pure types/traits)
                      +---------------------+
                        ^        ^        ^
                        |        |        |
              +---------+        |        +---------+
              |                 |                  |
   +----------+--------+   +----+-------------+   ++----------------+
   | balansir-control  |   | balansir-daemon |   | balansir-executor|
   | (control plane)   |   | (drivers+recon) |   | (priv kernel ops)|
   +-------------------+   +-----------------+   +------------------+
            ^                       ^                     ^
            |                       |                     |
            +----- depends on ------+                     |
                                    |                     |
                          +---------+---------+           |
                          |   balansir-api    |          |
                          |  (HTTP/axum port) |          |
                          +-------------------+          |
                                                        |
                              +-------------------------+
                              |   balansir-tests    |
                              | (integration tests) |
                              +---------------------+
```

- Циклов нет. `common` — leaf, никто из crate'ов не зависит обратно наверх.
- Проверено трассировкой всех 69 `use balansir_*` и всех `Cargo.toml [dependencies]`.

---

## 2. Границы модулей — где чисто

### 2.1 balansir-control — hexagonal-ядро

`crates/balansir-control/src/traits.rs` определяет 6 портов:

- `DesiredProvider`, `StateProvider`, `Planner`, `Executor`, `SnapshotStore`, `EventSink`
- + `Rollback` (пока живёт в `coordinator.rs:93`, стоит перенести в `traits.rs`)

`Coordinator` (`coordinator.rs:152`)_wireно собирается из `Config` (`Arc<dyn ...>`
семи портов). **Координатор не видит ни одного daemon-типа** — это эталон
гексагональной границы.

### 2.2 Драйверы — чистый lifecycle

Все 6 драйверов (`wireguard.rs`, `amneziawg.rs`, `xray.rs`, `hysteria.rs`, `b4.rs`,
`dns.rs`) реализуют только `ComponentDriver::{start, stop, restart, health_check}`.
**Ни один не выбирает "какой драйвер запустить"** — выбор делает `policy/mod.rs`
через `Action::Forward { driver: DriverId }`.

### 2.3 balansir-executor — изолирован

Executor не зависит от `daemon`/`control`. `lib.rs` = `pub mod executor; pub mod nftables;`,
`executor.rs` — trait + `DummyExecutor`, `nftables.rs` — shells out to `nft`.
Политики нет.

---

## 3. Где нарушена чистота — leaks

### 3.1 [HIGH] `DaemonRunner` вмещает 3 порта + inline-политику
`crates/balansir-daemon/src/reconciliation/mod.rs:243-334`

`DaemonRunner` одновременно реализует `StateProvider`, `Executor` и `Rollback`,
обернув один `Arc<Mutex<ActualState>>`. `impl Executor::execute` (`:255-324`):
- pattern-matches `ReconciliationOperation` (UpdatePolicy/RemovePolicy/NoOp, catch-all `_ => {}` — **молча проглатывает** `CreateDriver`/`DropDriver`);
- строит full `ActionRequest` + **синтезирует `DecisionTrace{policy_id:0, steps:[], correlation_id:0}`** — изобретает policy decision внутри executor-адаптера;
- мутирует `ActualState` напрямую.

Это смешивает read-state, execute и actual-store. Чисто: разделить на
`DaemonActualStore`, `DaemonExecutorAdapter`, `DaemonRollback`; actual-mutation
поднять в `Coordinator`/отдельный порт.

### 3.2 [HIGH] `Rollback` — paper rollback
`reconciliation/mod.rs:326-334`

`rollback()` восстанавливает только in-memory `ActualState`. Он **не отменяет**
nftables rules / `ip link` deletes, которые executor уже применил. Контракт `Rollback`
("восстановить систему") не выполняется. Координатор честно репортит `Failed`, но
откат физически неполный.

### 3.3 [HIGH] `balansir-api` не подключён к control plane
`crates/balansir-api/src/handlers.rs:23-96`

`balansir-api` не зависит ни от `daemon`, ни от `control`. Вместо использования
`Coordinator::reconcile(ApiRequest)` он держит собственный `ReconcilerHandle`
(stub) с `trigger_reconcile()`, который только инкрементирует counter (`:91-95`).
 Handlers `get_actual`, `list_drivers`, `restart_driver`, `get_drift` возвращают
hardcoded `{"rules":[]}` с `// TODO` (`:262, 292, 304, 316`).

`ReconcileReason::ApiRequest` объявлен (`events.rs:85`) и **никогда не используется**.

**Решение:** API должен зависеть от `balansir-control`, держать
`Arc<dyn DesiredProvider>` + триггерить `Coordinator::reconcile(ApiRequest)`.

### 3.4 [MEDIUM] Re-export фасадная утечка common-символов
`reconciliation/mod.rs:2-4` реэкспортирует `balansir_common::diff`, `plan`,
`ActualRule`, `ActualState` под namespace daemon'а. `tests/stress.rs:9` импортирует
`balansir_daemon::reconciliation::diff::StateDiff` — потребитель не понимает, что
тип живёт в `common`. Убрать re-export, импортировать из `balansir_common`.

### 3.5 [MEDIUM] `Rollback` trait не в `traits.rs`
Определён в `coordinator.rs:93`, рядом с потребителем, а не с пятью братьями в
`traits.rs`. Перенести вместе с `NoopRollback`.

---

## 4. Hardware/kernel vs pure policy — карта daemon crate

```
HARDWARE / KERNEL-TOUCHING          PURE POLICY / LOGIC
----------------------------------  ----------------------------------
netlink.rs:1-178   (rtnetlink)      policy/mod.rs:1-187
wireguard.rs:1-190 (ip + /sys)      policy/matcher.rs:1-313
amneziawg.rs:1-248 (lsmod + ip)     policy/rules.rs:1-190
xray.rs:1-204      (child + pgrep)  policy/fast_match.rs:1-172
hysteria.rs:1-374  (child + pkill) health.rs:1-182
b4.rs:1-275        (child + pkill)  reconciliation/mod.rs:1-377 (prod)
dns.rs:1-196       (ss)             reconciliation/bootstrap.rs:1-128
driver.rs:5-49     (trait defs)     main.rs:1-111 (IPC loop only)
```

`reconciliation/mod.rs` чистый (нет `Command`, нет `ip`, нет `/sys`) — вся
kernel-работа спрятана за `ExecutorAdapter`. Это **сильное место архитектуры**.

---

## 5. God-files / God-structs

### Files > 400 строк
| Lines | File | Вердикт |
|------:|------|---------|
| 481 | `balansir-daemon/src/reconciliation/mod.rs` | Flag. Содержит `Reconciler`, `Config`, `ExecutorAdapter`, `DaemonDesiredProvider`, `DaemonRunner` (3 trait impls), `TracingEventSink`, `DummyExecutorAdapter` + 3 теста. Разбить: `reconciler.rs` / `adapters.rs` / `sinks.rs` / `dummy.rs`. |
| 445 | `balansir-control/src/coordinator.rs` | Пограничный. FSM + Config + Coordinator + Rollback trait + 6 тестов. Перенести `Rollback` в `traits.rs`, тесты в `tests/coordinator.rs`. |

God-structs **не найдено** — у всех struct'ов cohesive fields. `Coordinator::Config`
держит 7 порт-trait-objects — это размер гексагона, естественен.

### Прочие структурные запахи
- `ReconcileReason::ApiRequest` (`events.rs:85`) объявлен — нигде не используется.
- `Reconciler::from_state_store` (`mod.rs:107`) дублирует `bootstrap::bootstrap` (`bootstrap.rs:8`) — проверить на dead code.
- `XrayDriver` имеет `Drop` (`xray.rs:116`), `Hysteria2Driver`/`B4Driver` — **нет**: дочерний процесс утечит, если `stop()` не вызвали (cleanup через `pkill -f` fragile).
- `DaemonRunner::execute` `_ => {}` проглатывает `CreateDriver`/`DropDriver` молча.

---

## 6. Сильные места (следует сохранить)

1. **Гексагональный `balansir-control`** — Coordinator видит только порты. Daemon можно
   заменить на Kubernetes controller, реализовав те же 6 трейтов.
2. **Строгая DAG зависимостей** — циклов нет, common — leaf.
3. **Драйверы = lifecycle-only** — ни одного inter-driver решения; выбор только через
   `Action::Forward`. Принцип "policy > mechanism" выдержан в коде.
4. **Executor изолирован** — нет `use balansir_daemon`/`control`, только DTO из `common`.
5. **Нулевые `unsafe`/`sh -c`/`expect`** в production-коде. Один production `unsafe`
   (`ipc.rs:72` getpeereid) — корректен и typed-mapped.
6. **CI полный**: fmt + clippy `-D warnings` + tests + матрица stable/nightly +
   кросс-сборка x86_64/aarch64/riscv64 + release по тегу.
7. **typed errors** (`thiserror`) в control plane и `balansir_common::Error`.

---

## 7. Рекомендуемые приоритеты (см. ROADMAP.md)

- **S1**Secutiry-runtime (Critical ×6): сокет в `/run/balansir/`, права 0600, секреты
  в `/run/balansir/` 0600, fsync StateStore, hardening executor systemd.
- **A1** API → control: подключить `Coordinator::reconcile(ApiRequest)`.
- **A2** `DaemonRunner` split + `Rollback` настоящий (через executor IPC undo).
- **A3** Policy engine ↔ Health: `evaluate(ctx, health_view)` + `rule.fallback`.
- **Q1** Async drivers: `tokio::process::Command` + `tokio::fs`.
