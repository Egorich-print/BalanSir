# BalanSir — Project State

> Последнее обновление: 2026-08-07
> Статус: Phase 0 (аудит) завершён; подготовка к Этапу 1 (архитектурное укрепление).

---

## 1. Что это

BalanSir — декларативный движок принятия решений для управления сетевой связностью
(**Policy-Based Network Execution Engine**). Пользователь описывает **намерение**
(политику), BalanSir самостоятельно строит план и приводит систему к желаемому
состоянию через взаимозаменяемые транспорты/overlay-драйверы.

Подробнее о стратегическом направлении — см. `STATUS.md` (раздел
«Направление развития: Policy-Based Network Execution Engine») и `README.ru.md`.

---

## 2. Workspace (crates)

> Текущее состояние (2026-08-17): workspace содержит **10 crate'ов**.
> Таблица ниже отражает исходный аудит (Phase 0, 2026-08-07, 6 crate'ов);
> добавлены `balansir-health`, `balansir-vpn`, `balansir-b4`, `balansir-ota`.

6 crate'ов, строгий ацикличный граф зависимостей (`common` — лист, остальные смотрят вниз).

| Crate | Роль | Зависит от |
|------|------|-----------|
| `balansir-common` | Базовые типы, IPC wire-protocol, StateStore, diff/plan, metrics, валидация | — |
| `balansir-control` | Control plane: 6 портов + `Rollback` + `Coordinator` FSM | `common` |
| `balansir-daemon` | Драйверы, policy engine, `Reconciler` (адаптер к `Coordinator`), IPC-сервер | `common`, `control` |
| `balansir-executor` | Привилегированный исполнитель: nftables + dummy | `common` |
| `balansir-api` | HTTP/Axum порт (health, metrics, drift, drivers, events+SSE) | `common` |
| `balansir-tests` | Интеграционные тесты IPC + netns (root-gated) | `common`, `executor` |

Слоирование проверено по всем `use balansir_*` — **нарушений нет**.

---

## 3. Ключевые архитектурные решения (кратко)

| Решение | Где зафиксировано | Реализовано |
|--------|-------------------|-------------|
| Hexagonal / control plane через порты | `crates/balansir-control/src/traits.rs` | ✅ Coordinator + 6 портов + Rollback |
| Разделение policy ↔ mechanism | `policy/mod.rs` `Action::Forward{driver}` vs `driver.rs::ComponentDriver` | ✅ драйверы не принимают решений |
| Двухпроцессная model (daemon непривилегированный, executor root) | `ADR-005` + `deploy/systemd/*.service` | ⚠️ частично (см. SECURITY ниже) |
| tokio `current_thread` runtime | `daemon/src/main.rs` | ✅ |
| State Store: Atomic Files + Ring Buffer | `ADR-001`, `common/src/state/file.rs` | ⚠️ нет fsync (crash-safety hole) |
| Гибридная модель драйверов (enum в prod, trait в SDK) | `ADR-002` | ✅ |

---

## 4. Числовые показатели аудита

- Исходных `.rs` файлов: 52 (на момент аудита)
- Тестов проходит: 381 workspace-тестов (2026-08-19), в т.ч. 231 в `balansir-daemon`,
  29 в `balansir-vpn`, 5 ignored под root
- CI: GitHub Actions — `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`
  на stable + nightly; кросс-сборка x86_64/aarch64/riscv64-musl; релиз по тегу.
- Найдено проблем в аудите (категоризовано в `ARCHITECTURE_AUDIT.md` + `TECH_DEBT.md`):
  - **Critical**: 6
  - **High**: 11
  - **Medium**: 16
  - **Low/Info**: ~15

---

## 5. Топ-5 приоритетов (см. `ROADMAP.md` для деталей)

1. **Безопасность runtime-окружения**: `/run/balansir/` вместо `/tmp/balansir-test/`,
   права 0600 на сокет, fsync в StateStore, секреты в `/run/balansir/` mode 0600.
2. **Hardening executor**: убрать `User=root`/`CAP_SYS_ADMIN`, добавить
   `NoNewPrivileges`/`ProtectSystem=strict`/`SystemCallFilter`, дроп caps в коде.
3. **API ↔ Coordinator**: `balansir-api` должен зависеть от `balansir-control` и
   вызывать `Coordinator::reconcile(ApiRequest)`, а не заглушку `ReconcilerHandle`.
4. **Policy engine ↔ Health**: `evaluate()` должен учитывать `HealthStatus` драйвера
   и использовать `rule.fallback` (сейчас мёртвое поле).
5. **Async-блокировки в драйверах**: `std::process::Command`/`std::fs` под
   `current_thread` runtime — перевести на `tokio::process`/`tokio::fs`/
   `spawn_blocking`.

---

## 6. Указатели по проекту

- Аудит архитектуры: [`ARCHITECTURE_AUDIT.md`](ARCHITECTURE_AUDIT.md)
- Технический долг: [`TECH_DEBT.md`](TECH_DEBT.md)
- Дорожная карта: [`ROADMAP.md`](ROADMAP.md)
- Статус/roadmap (operation): [`STATUS.md`](STATUS.md)
- ADR: [`docs/adr/`](docs/adr/) (`ADR-000..005` + будущие `ADR-006+`)
- Стратегическое видение: [`README.ru.md`](README.ru.md), раздел «Идея»
