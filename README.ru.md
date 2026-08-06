# BalanSir

<p align="center">
  <img src="docs/logo.svg" alt="BalanSir" width="200">
</p>

<h1 align="center">BalanSir</h1>

<p align="center">
  <strong>Декларативный движок принятия решений для управления сетевой связностью</strong>
</p>

<p align="center">
  <a href="https://github.com/Egorich-print/BalanSir/blob/main/README.md">English</a> •
  <a href="#идея">Идея</a> •
  <a href="#архитектура">Архитектура</a> •
  <a href="#примеры-политик">Политики</a> •
  <a href="#быстрый-старт">Быстрый старт</a> •
  <a href="#план-развития">План развития</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/status-alpha-yellow?style=flat-square" alt="Status">
</p>

---

## Идея

BalanSir — это не менеджер VPN и не «ещё один маршрутизатор трафика».

Проект развивается в сторону **универсального Policy-Based Network Execution Engine** — платформы, которая принимает декларативные политики пользователя и самостоятельно определяет, как должна быть организована сетевая связность.

> Пользователь описывает **что требуется**, а BalanSir самостоятельно определяет **как этого добиться**.

Система способна управлять практически любыми механизмами сетевой связности:

* VPN;
* Proxy;
* DPI Bypass;
* Mesh-сети;
* Overlay-сети;
* Zero Trust;
* SD-WAN;
* P2P-транспорт;
* сервисные туннели;
* технологии, которые ещё не существуют.

При этом архитектура **не зависит от конкретного протокола**.

### Что считается транспортом

Любой способ доставки сетевых пакетов — это **Transport Driver**:

- WireGuard, AmneziaWG, OpenVPN, Tailscale, Headscale;
- Xray / VLESS, Trojan, Hysteria2, TUIC, Shadowsocks;
- SOCKS5, HTTP Proxy, SSH Tunnel, QUIC Tunnel;
- собственные реализации и будущие протоколы.

Все они — лишь плагины. BalanSir не содержит бизнес-логику конкретного транспорта.

---

## Policy First

Политика всегда важнее транспорта. Пользователь описывает **намерение**, а BalanSir выбирает способ реализации:

- этот сайт использовать напрямую;
- этот сервис всегда через WireGuard;
- YouTube — через DPI bypass;
- GitHub — по самому быстрому каналу;
- Steam — через канал с минимальным RTT;
- рабочий трафик никогда не выводить через публичный VPN;
- если основной туннель недоступен — автоматически использовать резервный.

Решение принимает движок, автоматически.

---

## Архитектура

### Decision Engine — центр системы

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

Драйверы **не принимают решений** — они только исполняют.

### Capability Based

Драйвер сообщает не название, а **возможности**:

```text
supports:
  tunneling, udp, tcp, multiplexing, ipv6,
  userspace, kernelspace, obfuscation,
  congestion_control, dpi_resistance, low_latency
```

Decision Engine выбирает драйвер по способностям, а не по имени.

### Plan Engine

Движок не меняет систему сразу. Сначала строится **Execution Plan**:

```text
Текущее состояние:   WireGuard поднят, Xray выключен
Желаемое состояние:  WireGuard выключен, Hysteria2 поднят,
                     Policy Routing изменён, nftables обновлён
→ План изменений
→ Проверка → dry-run → explain → только затем применение
```

Так достигаются **атомарные изменения**.

### Driver Model

Каждый драйвер предоставляет единый интерфейс:

```text
capabilities()
probe()
apply()
rollback()
health()
metrics()
```

Никаких особых путей для отдельных драйверов.

### Безопасность (двухпроцессная архитектура)

- **Daemon** — непривилегированный, принимает решения, хранит состояние;
- **Executor** — минимальный объём кода, обладает привилегиями, выполняет только подтверждённый план.

IPC строго типизирован.

---

## Примеры политик

Пользователи описывают намерение, а не транспорт:

```text
# видео через DPI bypass
intent "youtube"        = via dpi-bypass

# Steam с минимальной задержкой
intent "steam"          = via lowest-rtt

# рабочий трафик — никогда в публичный VPN
intent "work-*"          = direct, forbid public-vpn

# автоматический резервный туннель
intent "default"        = wireguard, fallback hysteria2
```

BalanSir сам преобразует намерение в план и выбирает подходящие драйверы.

---

## Объяснимость и наблюдаемость

Любое решение должно объясняться и воспроизводиться.

- **Explain** — «почему выбран WireGuard»: соответствует политике, минимальный RTT, высокая доступность, разрешён пользователем.
- **Dry Run Everywhere** — почти любое изменение поддерживает симуляцию: «Что произойдёт, если применить новую конфигурацию?» — без изменения системы.
- **Observability** — каждое действие журналируется, имеет trace, explain и metrics.
- Интеграция с Prometheus, Grafana, OpenTelemetry, Loki и централизованными логами.
- **Runtime Reload** — изменение конфигурации не требует перезапуска демона.

---

## Быстрый старт

```bash
# Сборка
make build

# Установка (требует root)
sudo make install

# Конфигурация
sudo nano /etc/balansir/balansir.toml

# Запуск
sudo systemctl start balansir-daemon
sudo systemctl start balansir-executor
```

### Docker

```bash
docker run -d \
  --name balansir \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v /etc/balansir:/etc/balansir \
  -p 8080:8080 \
  balansir/balansir:latest
```

---

## Экосистема плагинов

Почти всё расширяемо:

- драйверы;
- политики;
- проверки состояния;
- механизмы выбора;
- источники конфигурации;
- экспортёры метрик.

Ядро знает как можно меньше о конкретных реализациях.

---

## План развития

См. [STATUS.md](STATUS.md) — текущий статус и дорожная карта, а также новое стратегическое направление развития проекта.

Долгосрочная цель — **«планировщик сети»**: как Kubernetes планирует контейнеры, BalanSir планирует сетевую связность между множеством транспортов. Транспорт перестаёт быть центральной сущностью. Главными становятся:

- политики (Policy);
- возможности (Capabilities);
- состояние системы;
- стоимость выполнения (Cost Model);
- качество канала (Health);
- требования пользователя (Intent).

Именно на их основе движок строит оптимальный план выполнения.

---

## Документация

- [Основа архитектурных решений](docs/adr/ADR-000-philosophy.md)
- [Модель драйверов](docs/adr/ADR-002-driver-model.md)
- [Разделение привилегий](docs/adr/ADR-005-privilege-separation.md)
- [Хранилище состояния](docs/adr/ADR-001-state-store.md)

---

## Лицензия

Лицензировано по одному из:

- Apache License, Version 2.0
- MIT License

по вашему выбору.