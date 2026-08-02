# Contributing to BalanSir

Thank you for your interest in contributing to BalanSir!

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch
4. Make your changes
5. Run tests
6. Submit a pull request

## Development Setup

```bash
# Clone
git clone https://github.com/Egorich-print/BalanSir.git
cd BalanSir

# Build
cargo build

# Run tests
cargo test

# Run linter
cargo clippy
```

## Architecture

BalanSir uses a layered architecture:

```
┌─────────────────────────────────────────────────────────┐
│                    balansir-daemon (unprivileged)       │
│  Policy Engine │ Reconciler Loop │ Health Monitor       │
├─────────────────────────────────────────────────────────┤
│                    balansir-executor (privileged)       │
│  Network Backend │ Driver Manager │ Resource Allocator  │
├─────────────────────────────────────────────────────────┤
│                    Linux Kernel (nftables/netlink)       │
└─────────────────────────────────────────────────────────┘
```

### Crates

- `balansir-common` — Types, IPC, State, Metrics
- `balansir-daemon` — Policy Engine, Drivers, Reconciler
- `balansir-executor` — Network Backend, nftables
- `balansir-api` — REST API + SSE (optional)
- `balansir-tests` — Integration tests

## Code Style

- Follow Rust standard conventions
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Add tests for new functionality
- Document public APIs

## Pull Request Process

1. Update documentation if needed
2. Add tests for new features
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Request review

## Reporting Issues

- Use GitHub Issues
- Include reproduction steps
- Include system information
- Include logs if applicable

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
