# BalanSir — Technical Debt

> Дата: 2026-08-07 | Категории: **Critical / High / Medium / Low / Info**
> Записи — `file:line`, краткое описание, ремедiatiom. Полный контекст в `ARCHITECTURE_AUDIT.md`.

---

## Critical

| ID | Область | Место | Проблема | Ремедиация |
|----|---------|-------|---------|-----------|
| C1 | Security/runtime | `balansir-daemon/src/main.rs:8` | Hardcoded сокет `/tmp/balansir-test/daemon.sock` противоречит systemd-юниту (`/run/balansir/`), world-traversable, symlink-race. | `/run/balansir/daemon.sock` + `set_permissions(0o600)` + socket activation. |
| C2 | Security/secrets | `xray.rs:143`, `hysteria.rs:205`, `b4.rs:126` | Конфиги (VLESS uuid, Hysteria password/obfs) пишутся в `/tmp/balansir-*-{id}.json` mode 0644 — world-readable. | `/run/balansir/<driver>-<id>.json` через `OpenOptionsExt::mode(0o600)` + wipe на Drop. |
| C3 | Privilege | `deploy/systemd/balansir-executor.service:17-22` | `User=root` + `CAP_SYS_ADMIN` + `NoNewPrivileges=no` + нет systemd hardening на executor. | `User=balansir-exec` + `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW` + `NoNewPrivileges=yes` + `ProtectSystem=strict` + `PrivateTmp=yes` + `SystemCallFilter=@system-service`; дроп caps в коде. |
| C4 | IPC trust | `balansir-executor/src/main.rs:16-21` | Executor слепо доверяет сокету — может подключиться к имперсонации под `/tmp/balansir-test/`. | Валидировать peer-uid с обеих сторон (`getpeereid`/SO_PEERCRED); challenge-response HMAC к shared secret в `/etc/balansir/secret` 0600. |
| C5 | nftables | `balansir-executor/src/nftables.rs:51-73` | `add_rule(rule: &str)` без эскейпинга/валидации — потенциальная инъекция в nft-синтаксис (`;`, newline). | Структурированный `NftRuleSpec { saddr, daddr, verdict, ... }` — бэкенд сам строит строку; либо `nft -c` превалидация. |
| C6 | IPC TOCTOU | `balansir-daemon/src/main.rs:23-25` | `remove_file(socket_path)` без inode/owner-check — TOCTOU при symlink. | `bind_unlink_safe`: удалять только если socket и st_uid == текущий uid; либо socket activation. |

---

## High

| ID | Область | Место | Проблема | Ремедиация |
|----|---------|-------|---------|-----------|
| H1 | Architecture | `balansir-api/src/handlers.rs:23-96` | API держит собственный stub `ReconcilerHandle` вместо `Coordinator`; `trigger_reconcile` только инкрементирует counter; 5 handlers — `// TODO` stubs. | Зависеть от `balansir-control`; `Arc<dyn DesiredProvider>` + `Coordinator::reconcile(ApiRequest)`. |
| H2 | Architecture | `reconciliation/mod.rs:243-334` | `DaemonRunner` вмещает 3 порта, `execute()` строит `ActionRequest`+`DecisionTrace` (inline-политика), мутирует actual; `_ => {}` проглатывает `CreateDriver`/`DropDriver`. | Разделить: `DaemonActualStore`/`DaemonExecutorAdapter`/`DaemonRollback`; actual-mutation наверх; `-`-arm логировать как unsupported. |
| H3 | Rollback | `reconciliation/mod.rs:326-334` | `Rollback::rollback` восстанавливает только in-memory `ActualState`, не отменяет kernel-операции. | Реальный undo через IPC `Action::undo`/`executor.undo()`, либо явный revert-plan. |
| H4 | Policy/Health | `policy/mod.rs:41-73` | `evaluate()` не учитывает `HealthStatus`; `rule.fallback` объявлен, но **никогда не читается** — failover мёртв. | `evaluate(ctx, &health_view)` → при `Forward{driver}` с `Unhealthy` пытаться `rule.fallback`. |
| H5 | Async/block | `wireguard.rs:50,66,78,95`, `amneziawg.rs:88,99,115,127,144`, `xray.rs:82,174`, `hysteria.rs:222,239,306`, `b4.rs:139,154,216`, `dns.rs:147` | `std::process::Command`/`std::fs` внутри `async fn` под `current_thread` runtime — блокирует весь runtime. | `tokio::process::Command` + `tokio::fs` + `spawn_blocking` для коротких `Path::exists`/`stat`. |
| H6 | IPC hardening | `main.rs:34-64` | Нет max-connections, rate-limit, timeouts; `tokio::spawn` per conn → DoS при `TasksMax=64`. | `Semaphore::new(N)` + per-conn message quota + `tokio::time::timeout` на recv. |
| H7 | IPC auth | `ipc.rs:9`, `balansir.socket:8-9` | `ALLOWED_UIDS=&[0]` но сокет mode 0660 `balansir:balansir` — executor под `balansir` не пройдёт. | Конфигурируемый список UID/GID; либо SocketUser=root. |
| H8 | StateStore durability | `state/file.rs:32-41` | Atomic-rename есть, но **нет fsync** → после power-loss 0-байтный файл. | `File::sync_all()` tmp до rename + fsync parent dir после. |
| H9 | StateStore path | `state/file.rs:25-26` | `key` прямо в `key_path`; нет allowlist `^[A-Za-z0-9_-]{1,32}$` — path-traversal при user-input ключе. | Валидация ключа; для `save("desired_state")` тривиально, но forward-compatible. |
| H10 | Binaries PATH | `wireguard.rs:50`, `nftables.rs:20`, `pgrep`/`pkill` | `Command::new("ip")`/`"nft"`/`"pgrep"` через PATH — уязвимость к подмене binary, особенно под strict systemd. | Абсолютные пути (`/usr/sbin/ip`, `/usr/sbin/nft`) через `which::which` на старте. |
| H11 | API bind | `balansir-api/src/lib.rs:119` | `0.0.0.0:<port>` — без auth/mTLS, открыт всем в LAN. | Default `127.0.0.1` + admin-token middleware + unix-socket опция. |

---

## Medium

| ID | Место | Проблема |
|----|-------|---------|
| M1 | `coordinator.rs:180,184,188,194` | `std::sync::Mutex::lock().unwrap()` — poison panic риск; заменить на `unwrap_or_else(\|e\| e.into_inner())` или `Atomic` для `CoordinatorState`. |
| M2 | `reconciliation/mod.rs:143,158,236,251,299,319` | Hot-path клон `DesiredState`/`ActualState` целиком при каждом reconcile; `Arc<DesiredState>` end-to-end убрал бы клоны. |
| M3 | `reconciliation/mod.rs:107,123,167,192,200`, `policy/rules.rs:55,84,133,142`, `profile.rs:72`, `api/lib.rs:116`, `tests/netns.rs:33+` | `Result<_, String>` вместо typed error — потеря структуры; внедрить `ControlError`/`PolicyError`/`ApiError`. |
| M4 | `wireguard.rs:11`, `amneziawg.rs:11`, `xray.rs:13`, `hysteria.rs:11-13,31-33` | Секреты в plain `String`; нет `secrecy::SecretString`/`zeroize`; нет `#[serde(skip_serializing)]` → риск случайного логирования `Debug`. |
| M5 | `nftables.rs:11-16` | `table_name`/`chain_name` — `String` без валидации `[A-Za-z0-9_-]`; валидировать на construction. |
| M6 | `state/file.rs:18`, `reconciliation/mod.rs:104` | StateStore directory создаётся с umask 0755 — world-readable; `DesiredState` содержит security-relevant policy. `DirBuilder::mode(0o700)`. |
| M7 | `xray.rs:174`, `hysteria.rs:239,306`, `b4.rs:154,216` | `pkill -f`/`pgrep -f` regex-match по всему cmdline системы; pgrep-matches-itself; убийство чужих процессов с тем же substr. Хранить `Child`, использовать `child.kill()`. |
| M8 | `xray.rs:116` vs `hysteria.rs`/`b4.rs` | `XrayDriver::Drop` чистит child; у Hysteria/B4 — нет, утечка child если не позвать `stop()`. |
| M9 | `rules.rs:108-113` | TOML `Action::Forward{driver}` → `DriverId::Custom(hash_domain(driver))` — никогда не матчит `DriverId::WireGuard` и т.д. Latent bug при подключении политик к execution. |
| M10 | `xray.rs:62-71`, `hysteria.rs:177-201` | JSON-конфиг через `format!` без эскейпинга — malformed JSON / config-injection при `"`,`\`. `serde_json::to_string` typed struct. |
| M11 | `version.rs:2` `check_state_compatibility` | Объявлен, не используется при load `desired_state` (`mod.rs:111-114`). Prepend `STATE_VERSION` в blob. |
| M12 | `state/file.rs:103` | Journal `len: u32` → `vec![0u8; len]` до 4 GiB allocation. Cap, как `MAX_PAYLOAD_SIZE`. |
| M13 | `ipc.rs:181-188` `request()` | Бесконечный loop на wrong `correlation_id`; no timeout. Bound N + `tokio::time::timeout`. |
| M14 | `netlink.rs:175`, `tests/netns.rs:156` | `getuid()==0` test-only — OK; `is_root()` в executor отсутствует — должен assert при старте. |
| M15 | `balansir.socket` vs `daemon/src/main.rs:8` | Path mismatch → systemd socket activation не сработает. Синхронизировать `/run/balansir/`. |
| M16 | `policy/mod.rs:44` | Default `Action::Allow` (fail-open) — для Network Policy Engine лучше default-deny (опционально per-profile). |

---

## Low / Info

| ID | Место | Проблема |
|----|-------|---------|
| L1 | `dns.rs:28,29` | `.parse().unwrap()` на константных строках — безопасно, но fragile к edit. |
| L2 | `hysteria.rs:182-183` | `parse::<u16>().unwrap_or(443)` маскирует malformed `server`. |
| L3 | `executor.rs:83-99` | `DummyExecutor` `async fn` держит `std::sync::Mutex` без await сегодня; задокументировать или `spawn_blocking`. |
| L4 | `reconciliation/mod.rs:2-4` | re-export common-символов — фасадная утечка; убирать. |
| L5 | `coordinator.rs:93` | `Rollback` trait не в `traits.rs` — переместить. |
| L6 | `events.rs:85` | `ReconcileReason::ApiRequest` не используется — ждать H1. |
| L7 | `coordinator.rs:311-314` | `ControlError::Executor(format!("... {}/{} "))` — счётчики в строке, не программно-извлекаемы. |
| L8 | `ipc.rs:72` | production `unsafe` getpeereid — корректен; на Linux предпочтительнее `SO_PEERCRED` (даёт pid). |
| L9 | `api/handlers.rs:213` | `serde_json::to_string(&entry).unwrap_or_default()` — SSE event silently теряется. `tracing::warn!`. |
| L10 | `wireguard.rs:7-24`, `amneziawg.rs:7-25` | `private_key` — dead field; драйвер никогда не зовёт `wg set private-key`. Помечено TODO; WG-интерфейс нефункционален. |
| L11 | global | нет `cargo-audit`/`cargo-deny` в CI — добавить для advisory CVE в deps. |
| L12 | `Makefile:78` | `config/balansir.toml` не существует — только `config/profiles/*.toml`. Документировать. |

---

## Rust-quality сводка

- `unwrap()` в production: **3** (`coordinator.rs:180/184/188/194` ×4 счётчика, `dns.rs:28-29`).
- `panic!` в production: **0** (все в `#[cfg(test)]`).
- `unsafe` production: **1** (`ipc.rs:72` getpeereid) — sound.
- `sh -c` / shell injection: **0** — все `Command::new` через `execvp`.
- Blocking-in-async (под current_thread): **~18 сайтов** в драйверах (H5).
- `Result<_, String>`: **11 сайтов** — M3.
- god-struct: **0**. God-files > 400 lines: **2** (`reconciliation/mod.rs`, `coordinator.rs`).

---

## Приоритизация выплат

**Быстро и дёшево с большим эффектом** (S-корткие правки, ремagor безопасности):
C1, C2, C3, H8 (fsync), H9 (key allowlist), H10 (absolute binaries), H7 (UID config),
L9 (warn on SSE fail). ~1–2 рабочих дня.

**Архитектурно (Этап 3)**: H1 (API→control), H2 (DaemonRunner split), H3 (real Rollback),
H4 (policy↔health fallback), H5 (async drivers), C5 (typed nftables).

Подробный порядок — в `ROADMAP.md`.
