# ADR-001: State Store

## Status

Accepted

## Context

Нужно хранить состояние компонентов, политик, событий на embeddedустройствах с ограниченной памятью.

## Decision

Используем trait `StateStore` с двумя backend'ами:

1. **FileStateStore** — atomic files для embeddedустройств (512MB RAM)
2. **RedbStateStore** — embedded ACID database для серверов (4GB+ RAM)

Backend выбирается через hardware profile при сборке.

```rust
pub enum StateStore {
    File(FileStateStore),
    #[cfg(feature = "redb")]
    Redb(RedbStateStore),
}
```

### FileStateStore

- Atomic write: write to tmp, then rename
- Ring buffer для event journal (mmap'd file, fixed size)
- Нет ACID, но minimal memory overhead

### RedbStateStore

- Full ACID transactions
- Higher memory overhead (4-8MB cache)
- Better for high-write scenarios

## Consequences

- Embedded устройства используют file backend
- Серверы могут использовать redb
- Единый интерфейс для обоих backend'ов
- Легко добавить новые backend'ы
