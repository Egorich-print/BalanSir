# Multi-stage build for BalanSir
FROM rust:1.75-slim as builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build dependencies first (cached)
RUN mkdir -p crates/balansir-common/src && echo "pub fn dummy() {}" > crates/balansir-common/src/lib.rs
RUN mkdir -p crates/balansir-daemon/src && echo "fn main() {}" > crates/balansir-daemon/src/main.rs
RUN mkdir -p crates/balansir-executor/src && echo "fn main() {}" > crates/balansir-executor/src/main.rs
RUN cargo build --release 2>/dev/null || true

# Build actual binaries
RUN touch crates/balansir-common/src/lib.rs crates/balansir-daemon/src/main.rs crates/balansir-executor/src/main.rs
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries
COPY --from=builder /app/target/release/balansir-daemon /usr/local/bin/
COPY --from=builder /app/target/release/balansir-executor /usr/local/bin/

# Create directories
RUN mkdir -p /etc/balansir /var/lib/balansir /var/log/balansir

# Copy default config
COPY config/ /etc/balansir/

# Expose ports
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["balansir-daemon"]
