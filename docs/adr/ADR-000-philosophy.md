# ADR-000: Project Philosophy

## Status

Accepted

## Context

BalanSir — Network Policy Engine для embedded Linuxустройств. Проект должен быть масштабируемым от Milk-V Duo S (512MB RAM) до x86 серверов.

## Decision

### Принципы

1. **BalanSir не реализует VPN-протоколы**, а оркестрирует их через драйверы.

2. **BalanSir строится поверх Linux networking stack** через стабильные интерфейсы (netlink, nftables, tc).

3. **Hardware profiles определяют поведение**, а не хардкод в архитектуре.

4. **Concrete types в production**, trait abstraction для SDK/testing.

5. **Binary IPC**, не serde для hot path.

6. **Каждый ADR появляется одновременно с реализацией** решения.

### Следствия

- Netlink вместо CLI (`nft`, `tc`, `ip`)
- Trait-based abstraction для SDK, enum для production
- Event-driven архитектура вместо polling
- State persistence через atomic files (embedded) или redb (server)
- Testing через DummyBackend

## Consequences

- Усложнение начальной разработки
- Более чистая архитектура в долгосрочной перспективе
- Легче добавлять новые протоколы
- Легче тестировать на разных платформах
