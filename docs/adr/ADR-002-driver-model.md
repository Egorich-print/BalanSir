# ADR-002: Driver Model

## Status

Accepted

## Context

Нужно поддерживать множество сетевых драйверов (WireGuard, Xray, Hysteria, B4) с возможностью расширения.

## Decision

Два режима:

### Production (default)

Enum с встроенными драйверами:

```rust
pub enum BuiltinDriver {
    WireGuard(WireGuardDriver),
    Xray(XrayDriver),
    Hysteria(HysteriaDriver),
    B4(B4Driver),
    Dummy(DummyDriver),
}

impl ComponentDriver for BuiltinDriver {
    fn id(&self) -> &str {
        match self {
            Self::WireGuard(d) => d.id(),
            // ...
        }
    }
}
```

### SDK mode (feature flag)

Dynamic dispatch для расширений:

```rust
#[cfg(feature = "sdk")]
pub type RegisteredDriver = Box<dyn ComponentDriver>;
```

### Driver Registry

Factory pattern для управления жизненным циклом:

```rust
pub struct DriverFactory {
    pub id: &'static str,
    pub capabilities: Capabilities,
    pub create: fn(&Profile) -> Box<dyn ComponentDriver>,
}
```

## Consequences

- Production binary minimal size (no vtables)
- SDK mode для third-party драйверов
- Factory pattern для чистого lifecycle management
- Нарушает Open/Closed при добавлении новых встроенных драйверов
