# BalanSir Status

> Last updated: 2026-08-06

## Направление развития: Policy-Based Network Execution Engine

BalanSir больше не рассматривается просто как менеджер VPN или маршрутизатор трафика.

Проект развивается в сторону **универсального Policy-Based Network Execution Engine** — платформы, которая принимает декларативные политики пользователя и самостоятельно определяет, каким образом должна быть организована сетевая связность.

Иными словами:

> Пользователь описывает **что требуется**, а BalanSir самостоятельно определяет **как этого добиться**.

### Главная цель

Создать систему, которая может управлять практически любыми механизмами сетевой связности:

* VPN;
* Proxy;
* DPI Bypass;
* Mesh-сети;
* Overlay-сети;
* Zero Trust;
* SD-WAN;
* P2P-транспорт;
* сервисные туннели;
* будущие технологии, которые ещё не существуют.

При этом сама архитектура не должна зависеть от конкретного протокола.

### Что считается транспортом

Любой способ доставки сетевых пакетов рассматривается как Transport Driver.

Например:

* WireGuard
* AmneziaWG
* Xray
* VLESS
* Trojan
* Hysteria2
* TUIC
* SOCKS5
* HTTP Proxy
* Shadowsocks
* OpenVPN
* SSH Tunnel
* QUIC Tunnel
* Tailscale
* Headscale
* собственные реализации
* будущие протоколы

Все они являются лишь плагинами.

BalanSir не должен содержать бизнес-логику конкретного транспорта.

### Policy First

Политика всегда важнее транспорта.

Например пользователь пишет:

* этот сайт использовать напрямую;
* этот сервис всегда через WireGuard;
* YouTube через DPI bypass;
* GitHub через наиболее быстрый канал;
* Steam через канал с минимальным RTT;
* рабочий трафик никогда не выводить через публичный VPN;
* если основной туннель недоступен — автоматически использовать резервный.

BalanSir принимает решение автоматически.

### Decision Engine

Центром системы становится движок принятия решений.

Схема выглядит так:

```text
Matcher
    ↓
Policy Evaluation
    ↓
Decision
    ↓
Execution Plan
    ↓
Drivers
```

Драйверы не принимают решений. Они только исполняют.

### Plan Engine

Следующий крупный этап развития.

Decision Engine не должен сразу менять систему.

Сначала он строит Execution Plan.

Например:

Текущее состояние:

* WireGuard поднят
* Xray выключен

Желаемое:

* выключить WireGuard
* поднять Hysteria2
* изменить Policy Routing
* обновить nftables

Получается план изменений.

После этого план проходит:

* проверку;
* dry-run;
* explain;
* только затем применяется.

Таким образом появляется возможность атомарных изменений.

### Driver Model

Каждый драйвер предоставляет одинаковый интерфейс.

Например:

```text
capabilities()
probe()
apply()
rollback()
health()
metrics()
```

Никаких специальных путей для отдельных драйверов быть не должно.

### Capability Based Architecture

Драйвер сообщает не своё название, а возможности.

Например:

```text
supports:
  tunneling, udp, tcp, multiplexing, ipv6,
  userspace, kernelspace, obfuscation,
  congestion_control, dpi_resistance, low_latency
```

Decision Engine выбирает драйвер по возможностям.

Не по имени.

### Explainability

Любое решение должно объясняться.

Например:

«Почему используется WireGuard?»

Ответ:

* удовлетворяет политике;
* минимальный RTT;
* высокая доступность;
* разрешён пользователем.

Любое решение должно быть воспроизводимым.

### Dry Run Everywhere

Практически любое изменение должно поддерживать режим симуляции.

Пользователь должен иметь возможность получить ответ: «Что произойдёт, если применить новую конфигурацию?»

Без изменения системы.

### Observability

BalanSir должен быть максимально наблюдаемым.

Каждое действие:

* журналируется;
* имеет trace;
* имеет explain;
* имеет metrics.

Система должна легко интегрироваться с:

* Prometheus;
* Grafana;
* OpenTelemetry;
* Loki;
* централизованными логами.

### Runtime Reload

Изменение конфигурации не должно требовать перезапуска демона.

Любая политика должна иметь возможность обновляться во время работы.

### Безопасность

Архитектура остаётся двухпроцессной.

Daemon:

* непривилегированный;
* принимает решения;
* хранит состояние.

Executor:

* минимальный объём кода;
* обладает привилегиями;
* выполняет только подтверждённый план.

IPC остаётся строго типизированным.

### Plugin Ecosystem

Практически всё должно быть расширяемым:

* драйверы;
* политики;
* проверки состояния;
* механизмы выбора;
* источники конфигурации;
* экспортёры метрик.

Ядро должно знать как можно меньше о конкретных реализациях.

### Долгосрочное направление

В долгосрочной перспективе BalanSir должен стать аналогом «планировщика сети».

Как Kubernetes планирует контейнеры, а Vivanta в будущем будет планировать выполнение вычислений между различными ускорителями, так и BalanSir должен планировать сетевую связность между множеством возможных транспортов.

Транспорт перестаёт быть центральной сущностью.

Главной сущностью становятся:

* политики;
* возможности (Capabilities);
* состояние системы;
* стоимость выполнения (Cost Model);
* качество канала (Health);
* требования пользователя (Intent).

Именно на их основе движок строит оптимальный план выполнения.

### Архитектурный принцип

BalanSir — это не VPN-менеджер.

BalanSir — это декларативный движок принятия решений для управления сетевой связностью.

Все сетевые технологии рассматриваются как взаимозаменяемые исполнительные механизмы, а ядро проекта отвечает исключительно за анализ состояния, интерпретацию политик, построение плана действий и координацию исполнения. Такое разделение делает систему масштабируемой, расширяемой и независимой от конкретных протоколов, позволяя интегрировать новые транспортные технологии без изменения архитектуры ядра.

---

## Current Phase: Planning v0.5.0 — Enterprise-Grade Control Plane & Self-Healing

### v0.5.0 Roadmap
1. **Configuration Reconciliation**
   - [x] StateDiff & ReconciliationPlan abstraction (Completed)
   - [ ] Hot Reload & Atomic Config Swap
   - [ ] Dry-run mode (`--dry-run`)
   - [ ] Configuration versioning & rollback
2. **Control Plane**
   - Expanded HTTP Control API (`/status`, `/drivers`, `/rules`, `/drain`, etc.)
   - Runtime Driver Lifecycle (`enable`, `disable`, `start`, `stop`, `restart`)
   - Graceful Drain (no connection drops on reload)
3. **Observability & Health Engine**
   - Health Engine with multi-tier states (`Healthy` → `Degraded` → `Failing` → `Disabled`)
   - Enhanced Prometheus Metrics
4. **Policy Engine v2**
   - Universal matchers (protocols, IPs, ports, latency, metadata)
5. **Event System**
   - Internal Event Bus for state changes and plugins

### Completed

- [x] Architecture specification (v7.0)
- [x] ADR-000 through ADR-011
- [x] Hardware profiles design
- [x] IPC protocol (postcard-based)
- [x] Workspace setup
- [x] balansir-common crate
- [x] balansir-daemon skeleton
- [x] balansir-executor skeleton
- [x] StateStore (file backend)
- [x] BoundedEventBus (Arc<Inner> pattern)
- [x] ResourceAllocator
- [x] NftablesBackend
- [x] Drivers:
  - [x] WireGuard (feature flag)
  - [x] AmneziaWG (feature flag)
  - [x] Xray (VLESS) (feature flag)
  - [x] Hysteria 2 (feature flag)
  - [x] B4 (feature flag)
  - [x] DNS Forwarder (feature flag)
- [x] Decision Trace
- [x] Event ID (monotonic)
- [x] Correlation ID for IPC
- [x] Time abstraction (Clock trait)
- [x] Policy Engine (matchers, actions)
- [x] Health Monitor (circuit breaker)
- [x] Action Model (Route, Mark, Forward, Block, Reject)
- [x] Executor trait + DummyExecutor
- [x] Full IPC integration tests
- [x] DriverId newtype
- [x] ActionResult enrichment
- [x] Network namespace tests
- [x] Reconciliation loop
- [x] Crash recovery (bootstrap)
- [x] GitHub Actions CI/CD
- [x] Polished code (clippy, unwrap fixes, docs)
- [x] Prometheus metrics (/metrics endpoint)
- [x] REST API (axum)
- [x] SSE Event Stream (/events/stream)
- [x] Web UI (Svelte dashboard)
- [x] Graceful shutdown (SIGTERM/SIGINT)
- [x] Configuration validation
- [x] Docker image (multi-stage)
- [x] docker-compose.yml
- [x] Phase A: IPC Authentication (SO_PEERCRED)
- [x] Phase A: MAX_MESSAGE_SIZE validation
- [x] Phase A: DriverError enum (typed errors)
- [x] Phase A: Feature flags for external binaries
- [x] Phase A: BoundedEventBus Clone fix (Arc<Inner>)
- [x] Phase B: Native netlink (Linux only)
- [x] Phase B: Go runtime memory guardrails (GOMEMLIMIT/GOGC)
- [x] Phase B: Atomic rollback + watchdog
- [x] Phase B: Missing API endpoints (/ready, /live, /version, /build-info, /drivers)
- [x] Phase B: Property testing (proptest)
- [x] Phase C: DriverId as enum (exhaustive matching)
- [x] Phase C: Matcher recursion limit (depth 16)
- [x] Phase C: L3/L7 driver trait split
- [x] Phase C: DomainMatcher/PortMatcher fast lookup
- [x] Phase C: Policy Trie optimization
- [x] Phase D1: Binary size optimization (daemon 704KB, executor 655KB)
- [x] Phase D2: CONTRIBUTING.md + scripts/balansir-cli
- [x] Phase D3: Stress testing
  - [x] Policy engine: 1000+ rules, timing measured
  - [x] Reconciliation: 24h simulation (2880 cycles, rule churn)
  - [x] EventBus: 100k burst, drop-oldest semantics, concurrent publishers
  - [x] IPC: 10k message burst over Unix socket
  - [x] Fixed EventBus publish() race (ID assignment moved under mutex)

### Next

- [ ] v0.1.0 release (tag, CHANGELOG)
- [ ] Verify `make install` on macOS
- [ ] Push to Forgejo backup

## Architecture Decisions

| Decision | Status | ADR |
|----------|--------|-----|
| StateStore backend | ✅ File (default), Redb (optional) | ADR-001 |
| Driver model | ✅ Enum in prod, dyn in SDK | ADR-002 |
| Runtime | ✅ current_thread (embedded), multi_thread (desktop) | ADR-003 |
| IPC | ✅ postcard + length framing | ADR-004 |
| Privilege separation | ✅ daemon + executor | ADR-005 |
| Health | ✅ Circuit breaker | ADR-006 |
| Updates | ✅ A/B slots | ADR-007 |
| Reconciliation | ✅ Desired state + drift detection | ADR-008 |
| Observability | ✅ Prometheus metrics | ADR-009 |
| API | ✅ REST + SSE | ADR-010 |
| IPC Auth | ✅ SO_PEERCRED | ADR-011 |
| Error Typing | ✅ DriverError enum | ADR-012 |

## Drivers

| Driver | Status | Capabilities | Obfuscation |
|--------|--------|--------------|-------------|
| WireGuard | ✅ Complete | TUNNEL | No |
| AmneziaWG | ✅ Complete | TUNNEL | Yes (AWG params) |
| Xray (VLESS) | ✅ Complete | PROXY | Yes (XTLS) |
| Hysteria 2 | ✅ Complete | PROXY | Yes (salamander) |
| B4 | ✅ Complete | PACKET_PROCESSOR | Yes (fragmentation) |
| DNS Forwarder | ✅ Stub | DNS | N/A |

## Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| Daemon RSS | ≤ 12MB | TBD (target device) |
| Executor RSS | ≤ 8MB | TBD (target device) |
| Policy eval | < 100µs | ~10.9µs (debug, 1024 rules) |
| Firewall apply | < 50ms | TBD (target device) |

## GitHub

**Repository:** https://github.com/Egorich-print/BalanSir

**Tests:** 486 passing (2026-08-18), 5 ignored (require root); incl. 231 daemon, 33 vpn

## Docker

```bash
docker-compose up -d
```

## Web UI

```bash
cd webui && npm install && npm run dev
# http://localhost:5173
```
