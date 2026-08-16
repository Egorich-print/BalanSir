# BalanSir — Architecture (canonical)

> Единый канонический архитектурный документ. Дата ревизии: 2026-08-16.
> Отражает фактический код (`crates/`, main: HEAD). Устаревшие версии: `docs/ARCHITECTURE_AUDIT_2026-08-14.md`.

---

## 1. Назначение

Прозрачный шлюз (RPi 3B+ / Proxmox VM / QEMU) между ISP WAN и LAN:
USB-WAN / eth0-LAN с явными ролями портов, MAC-клонирование, DNS-фильтрация
(Pi-hole role), NAT, B4 (path-MTU / DPI), VPN-туннели, OTA. Код — Rust,
workspace из 10 crates.

## 2. Workspace (10 crates) и границы

```
balansir-common    базовый слой: DTO, Action, Matcher types, IPC (postcard), QoS, ops
balansir-control   hexagonal control plane: traits {DesiredProvider, StateProvider,
                   Planner, Executor, SnapshotStore, EventSink, Rollback} + Coordinator
balansir-daemon    unprivileged daemon: policy engine, drivers, reconciliation, DNS,
                   B4 (b4_dpi + b4_engine + b4_manager), network_config, VPN/Xray mgr
balansir-executor  privileged: shell-out to ip/nft/tailscale/... по whitelist-операциям
balansir-api       HTTP (axum): админ-API, подключается к control plane через reconciler
balansir-b4        DPI-движок (NFQUEUE sniffing): извлечение SNI/TLS, классификация
balansir-vpn       VPN-абстракции (wireguard/amneziawg/hysteria/xray)
balansir-health    health-телефония для policy engine
balansir-ota       A/B-слоты, подписанные манифесты, rollback
balansir-tests     интеграционные тесты
```

Зависимости: `common` — leaf. `daemon`/`control` не зависят от `executor` напрямую —
только через DTO из `common` (IPC поверх unix-socket, postcard). Циклов нет.

## 3. Модель политики (единая)

- `crates/balansir-daemon/src/policy/` — `PolicyEngine`, `PolicyRule { matcher: Matcher, action: Action }`.
- `Action` — `crates/balansir-common/src/types.rs:281`: `Route | Mark | Forward { driver } | Block | Reject | Allow | Shape | Log | Queue { num }`.
- Цепочка целостности: **Matcher → Decision → Executor**. Решение принимает policy,
  исполнение — только через IPC в executor. Daemon не трогает kernel напрямую.
- Решение по каждому новому соединению принимает `path_decision` (`path_decision.rs`),
  классификацию даёт `dns_plane`/`DnsRegistry` + `b4_dpi`.
- **Единый словарь**: нет параллельных enum'ов для классификации DNS. Старый
  `DnsClassification {Direct,Block,B4,Vpn}` удалён вместе с мёртвым `dns_filter.rs`.

## 4. DNS (канонический стек)

- **Единственный listener**: `crates/balansir-daemon/src/dns.rs` (`DnsForwarderDriver`,
  wired в `main.rs` через `BALANSIR_DNS_CONFIG`). UDP-форвардер, round-robin failover по upstreams.
- **Фильтрация встроена** (Pi-hole role): `DnsForwarderConfig { blocklist, allowlist }`.
  Домен извлекается через `dns_plane::query_name`; суффикс-матчинг (запись покрывает
  домен и поддомены); `allowlist` перекрывает `blocklist`. Заблокированный запрос
  отвечается NXDOMAIN локально, **в upstream не уходит** и в registry не попадает.
- **Наблюдения**: каждый пропущенный ответ идёт через `dns_plane::ingest(registry, query, resp)`
  (`dns_plane.rs:301`) в общий `DnsRegistry` (`reconciliation/dns_flow.rs`, `DnsRegistry::insert`).
  Registry — единственная точка истины "домен → IP" для flow compiler и B4.
- Cached-ответы не пере-парсятся (TTL кеша ограничивает свежесть registry).

## 5. Gateway / роли портов

- Канон: `network_config.rs` + `main.rs::apply_network_config` (роли WAN/LAN,
  MAC-клонирование через executor `InterfaceOp::SetMac/RestoreMac`).
- Мёртвые дубликаты **удалены**: `gateway.rs` и `upnp.rs` (не компилировались,
  ссылались на несуществующие executor-операции `set_interface_ip/enable_nat/
  enable_forwarding/mgmt_firewall/set_mac/add_dnat/remove_dnat`).
- **Реальный пробел**: executor НЕ имеет NAT / firewall / DNAT / IP-forwarding /
  set-ip операций (`InterfaceOp` — только Get/SetMac/RestoreMac). NAT и UPnP на шлюзе
  **не реализованы** — это открытая фича (см. §9).

## 6. Executor IPC surface (подтверждено)

`balansir-common`:
- `InterfaceOp { Get, SetMac, RestoreMac }` — `network.rs:136`
- `TailscaleOp { Status, Up, Down, Reconnect, SetRoutes }` — `network.rs:110`
- `QosOp` — `qos.rs:175`
- `DpiOp` — `types.rs:534` (DPI-bypass queue rules)
- `MsgType::QosOp | DpiOp | ...` — `ipc.rs:53-67`

Нет операций NAT/firewall/DNAT/SetInterfaceIp → фича незакрыта, не дублирована.

## 7. Startup flow (main.rs)

`startup::load_startup_desired` → `Reconciler::new` → `sync_actual_from_executor`
(inventory) → **initial reconcile** (fail-close: недоступность → откат, ActualState
не мутируется) → `apply_network_config(executor)` (роли+MAC) →
`reconciler.run_loop()` + `dns_loop()` (DnsForwarder + ingest в registry) →
flow compiler подключён → `b4_manager::B4Manager` (path-MTU контроллер per-flow) →
`b4_dpi::DpiManager` (NFQUEUE) → xray/vpn manager → `server::api_bind()` (HTTP API).

## 8. Известные точки переработки / чистые места

- **Чисто**: `balansir-control` гексагонален (Coordinator видит только порты).
  Daemon-адаптеры расщеплены: `reconciliation/adapters.rs` —
  `DaemonActualStore`, `DaemonDesiredProvider`, `DaemonExecutorAdapter`,
  `DaemonRollback` (устаревший монолит `DaemonRunner` больше не существует).
- **API подключён к control plane** (`plane.reconcile_api()`, `trigger_reconcile`).
- **Сильно**: kernel-работа спрятана за executor IPC; daemon не содержит
  прямых `Command`/nftable-вызовов в policy-пути; 0 `unsafe` (кроме getpeereid в IPC).
- **Форматирование**: часть файлов имеет fmt-отклонения (network_config, vpn_manager,
  ota/slot) — артефакт параллельных правок; CI fmt не пройден до их фиксации.

## 9. Открытые фичи / blockers (не дубликаты)

1. **NAT/UPnP/management firewall не реализованы** — executor не имеет соответствующих ops.
2. **B4 TCP reassembly** фрагментированного ClientHello отсутствует (`balansir-b4/src/{engine,packet}.rs`,
   `extract_tls_sni` возвращает None при фрагментации) — базовое требование пути B4.
3. **Xray `allowInsecure`** (`daemon/src/xray.rs:208`) несовместим с xray 26.7.28.
4. QEMU slirp: смена MAC активного eth0 рвёт сеть (свойство user-mode networking).
5. Rootfs VM эфемерный — пересборка: `sync-to-vm.sh 2222` (после commit), builder `/home/builder/br-qemu`, `make balansir-rebuild all`.

## 10. Как добавлять новую фичу (ownership map)

| Слой | Что здесь живёт | Куда добавлять |
|------|-----------------|----------------|
| config/decision | правила, Action, роли | `policy/`, `types.rs`, `network_config.rs` |
| DNS-наблюдения | домен→IP для policy | `dns.rs` (listener), `dns_plane::ingest` → `DnsRegistry` |
| kernel-операции | ip/nft/tailscale | `balansir-executor` (новая Op в `common` + whitelist) |
| B4 | DPI sniff / path-MTU | `balansir-b4` (engine), `b4_dpi.rs`, `b4_manager.rs` |
| Xray/VPN | туннели | `xray.rs`/`xray_manager.rs`, `vpn_manager.rs`, `balansir-vpn` |
| OTA | A/B обновления | `balansir-ota` |

Правило: **новое kernel-касание — только через executor Op**. Daemon никогда
не вызывает `ip`/`nft` напрямую.
