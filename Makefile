# BalanSir - Network Policy Engine
# Makefile for building and installing from source

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
CONFDIR ?= /etc/balansir
DATADIR ?= /var/lib/balansir
LOGDIR ?= /var/log/balansir
SYSTEMDDIR ?= /etc/systemd/system

CARGO ?= cargo
CARGO_FLAGS ?= --release

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    OS := linux
else ifeq ($(UNAME_S),Darwin)
    OS := macos
else
    OS := unknown
endif

.PHONY: all build install uninstall clean test check

all: build

build:
	$(CARGO) build $(CARGO_FLAGS)
	@echo "Build complete. Binaries in target/release/"

test:
	$(CARGO) test
	@echo "Tests complete."

check:
	$(CARGO) check
	$(CARGO) clippy -- -D warnings
	@echo "Check complete."

install: build install-bin install-config install-systemd
	@echo ""
	@echo "========================================="
	@echo "BalanSir installed successfully!"
	@echo "========================================="
	@echo ""
	@echo "Configuration: $(CONFDIR)/"
	@echo "Data:          $(DATADIR)/"
	@echo "Logs:          $(LOGDIR)/"
	@echo ""
	@echo "Quick start:"
	@echo "  1. Edit config:  sudo nano $(CONFDIR)/balansir.toml"
	@echo "  2. Start daemon: sudo systemctl start balansir-daemon"
	@echo "  3. Start exec:   sudo systemctl start balansir-executor"
	@echo "  4. Check status: balansir-cli status"
	@echo ""

install-bin:
	@echo "Installing binaries..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 target/release/balansir-daemon $(DESTDIR)$(BINDIR)/
	install -m 755 target/release/balansir-executor $(DESTDIR)$(BINDIR)/
	@# Create CLI wrapper
	install -m 755 scripts/balansir-cli $(DESTDIR)$(BINDIR)/

install-config:
	@echo "Installing configuration..."
	install -d $(DESTDIR)$(CONFDIR)
	install -d $(DESTDIR)$(CONFDIR)/profiles
	install -d $(DESTDIR)$(DATADIR)
	install -d $(DESTDIR)$(LOGDIR)
	@if [ ! -f $(DESTDIR)$(CONFDIR)/balansir.toml ]; then \
		echo "Creating default configuration..."; \
		install -m 644 config/balansir.toml $(DESTDIR)$(CONFDIR)/; \
		install -m 644 config/profiles/*.toml $(DESTDIR)$(CONFDIR)/profiles/; \
	else \
		echo "Configuration exists, skipping (use 'make install-config-force' to overwrite)"; \
	fi

install-config-force:
	@echo "Force installing configuration..."
	install -d $(DESTDIR)$(CONFDIR)
	install -d $(DESTDIR)$(CONFDIR)/profiles
	install -m 644 config/balansir.toml $(DESTDIR)$(CONFDIR)/
	install -m 644 config/profiles/*.toml $(DESTDIR)$(CONFDIR)/profiles/

install-systemd:
	@if [ "$(OS)" = "linux" ]; then \
		echo "Installing systemd units..."; \
		install -d $(DESTDIR)$(SYSTEMDDIR); \
		install -m 644 deploy/systemd/balansir-daemon.service $(DESTDIR)$(SYSTEMDDIR)/; \
		install -m 644 deploy/systemd/balansir-executor.service $(DESTDIR)$(SYSTEMDDIR)/; \
		install -m 644 deploy/systemd/balansir.socket $(DESTDIR)$(SYSTEMDDIR)/; \
		systemctl daemon-reload; \
	else \
		echo "Skipping systemd (not Linux)"; \
	fi

uninstall:
	@echo "Uninstalling BalanSir..."
	rm -f $(DESTDIR)$(BINDIR)/balansir-daemon
	rm -f $(DESTDIR)$(BINDIR)/balansir-executor
	rm -f $(DESTDIR)$(BINDIR)/balansir-cli
	rm -f $(DESTDIR)$(SYSTEMDDIR)/balansir-daemon.service
	rm -f $(DESTDIR)$(SYSTEMDDIR)/balansir-executor.service
	rm -f $(DESTDIR)$(SYSTEMDDIR)/balansir.socket
	@if [ "$(OS)" = "linux" ]; then \
		systemctl daemon-reload; \
	fi
	@echo "Note: Configuration and data preserved at $(CONFDIR) and $(DATADIR)"
	@echo "Remove manually if needed."

clean:
	$(CARGO) clean
	@echo "Clean complete."

# Development targets
dev:
	$(CARGO) build
	@echo "Development build complete."

run-daemon: dev
	./target/debug/balansir-daemon

run-executor: dev
	sudo ./target/debug/balansir-executor

# Package targets
deb: build
	@echo "Building Debian package..."
	@mkdir -p target/deb
	@cp target/release/balansir-daemon target/deb/
	@cp target/release/balansir-executor target/deb/
	@cp scripts/balansir-cli target/deb/
	@echo "Use 'dpkg-deb' to create .deb package"

rpm: build
	@echo "Building RPM package..."
	@echo "Use 'rpmbuild' to create .rpm package"

# Help
help:
	@echo "BalanSir - Network Policy Engine"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build release binaries"
	@echo "  build            - Build release binaries"
	@echo "  test             - Run tests"
	@echo "  check            - Run clippy and checks"
	@echo "  install          - Install system-wide"
	@echo "  uninstall        - Remove installed files"
	@echo "  clean            - Remove build artifacts"
	@echo "  dev              - Build debug binaries"
	@echo "  run-daemon       - Run daemon in debug mode"
	@echo "  run-executor     - Run executor in debug mode (requires root)"
	@echo "  help             - Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX           - Installation prefix (default: /usr/local)"
	@echo "  CONFDIR          - Configuration directory (default: /etc/balansir)"
	@echo "  DATADIR          - Data directory (default: /var/lib/balansir)"
