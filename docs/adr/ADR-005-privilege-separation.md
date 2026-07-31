# ADR-005: Privilege Separation

## Status

Accepted

## Context

Сетевые операции требуют root привилегий (nftables, netlink, WireGuard). API и policy engine не должны работать с root.

## Decision

Два процесса:

### balansir-daemon (unprivileged)

- UID: balansir
- Capabilities: none
- Отвечает за: API, Policy Engine, State Store, Health Monitor
- RSS limit: 12MB (embedded), 128MB (server)

### balansir-executor (privileged)

- UID: root
- Capabilities: CAP_NET_ADMIN, CAP_NET_RAW
- Отвечает за: Network Backend, Driver Runner, Resource Allocator
- RSS limit: 8MB (embedded), 64MB (server)

### IPC

Unix Domain Socket: `/run/balansir/daemon.sock`

Binary protocol (postcard):

```rust
pub struct IpcMessage {
    pub version: u8,
    pub msg_type: MsgType,
    pub sequence: u32,
    pub payload: Vec<u8>,
}
```

## Consequences

- Security: API compromise не даёт root access
- Complexity: два процесса для управления
- Performance: IPC overhead (minimal для binary protocol)
- Testing: можно тестировать daemon без root
