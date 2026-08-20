################################################################################
#
# balansir
#
# Builds the BalanSir network policy engine from the workspace root. The
# workspace contains three binaries: balansir-daemon + balansir-cli (in
# crates/balansir-daemon) and balansir-executor (in crates/balansir-executor).
# cargo-package builds with --bins; passing --workspace makes cargo build the
# binaries of every member crate.
#
# The workspace root is a virtual manifest, so Cargo.lock resolves all crates.
#
# SITE_METHOD = local: build from the checked-out repository the external
# tree lives in. The external tree sits at <repo>/buildroot-external, so the
# repo root is one level up (BR2_EXTERNAL_BALANSIR_PATH/..), NOT ../.. (that
# would recurse into the build host's parent dir and re-copy the output tree).
# A git SITE can be substituted (BALANSIR_SITE_METHOD = git) for CI builds
# from a pushed tag.
BALANSIR_VERSION = 0.4.0
BALANSIR_SITE = $(BR2_EXTERNAL_BALANSIR_PATH)/..
BALANSIR_SITE_METHOD = local
BALANSIR_LICENSE = MIT OR Apache-2.0
BALANSIR_LICENSE_FILES = LICENSE-MIT LICENSE-APACHE

# Build every workspace binary (daemon, cli, executor).
BALANSIR_CARGO_BUILD_OPTS = --workspace

# cargo-package's automatic vendoring runs only for tarball/git downloads
# (cargo-post-process), NOT for SITE_METHOD=local. So vendor here, before the
# (offline, --locked) build, and point cargo at the vendor dir via .cargo/config.
define BALANSIR_VENDOR_DEPS
	cd $(BALANSIR_SRCDIR) && \
	$(HOST_DIR)/bin/cargo vendor --locked --manifest-path Cargo.toml VENDOR && \
	printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "VENDOR"\n' > .cargo/config
endef
BALANSIR_PRE_BUILD_HOOKS = BALANSIR_VENDOR_DEPS

# The workspace root is a virtual manifest, so `cargo install` fails. Install
# the built binaries directly from the cargo target dir (cross-compiled).
# Install into /usr/local/bin to match the deploy/systemd units' ExecStart
# (ADR-030); Buildroot's default /usr/bin is not what the units reference.
define BALANSIR_INSTALL_TARGET_CMDS
	# Remove stale copies from earlier builds that installed to /usr/bin.
	rm -f $(TARGET_DIR)/usr/bin/balansir-daemon \
	      $(TARGET_DIR)/usr/bin/balansir-cli \
	      $(TARGET_DIR)/usr/bin/balansir-executor
	mkdir -p $(TARGET_DIR)/usr/local/bin
	install -m 0755 $(BALANSIR_SRCDIR)/target/$(RUSTC_TARGET_NAME)/release/balansir-daemon \
		$(TARGET_DIR)/usr/local/bin/
	install -m 0755 $(BALANSIR_SRCDIR)/target/$(RUSTC_TARGET_NAME)/release/balansir-cli \
		$(TARGET_DIR)/usr/local/bin/
	install -m 0755 $(BALANSIR_SRCDIR)/target/$(RUSTC_TARGET_NAME)/release/balansir-executor \
		$(TARGET_DIR)/usr/local/bin/
	# OTA installer (A/B slot management, mission §13): installed only when the
	# operator enables BR2_PACKAGE_BALANSIR_OTA (default on).
ifeq ($(BR2_PACKAGE_BALANSIR_OTA),y)
	install -m 0755 $(BALANSIR_SRCDIR)/target/$(RUSTC_TARGET_NAME)/release/balansir-ota \
		$(TARGET_DIR)/usr/local/bin/
endif
	# Daemon unit (ADR-030) uses ProtectSystem=strict with
	# ReadWritePaths=/var/lib/balansir /var/log/balansir — create them.
	mkdir -p $(TARGET_DIR)/var/lib/balansir $(TARGET_DIR)/var/log/balansir
	# WebUI static assets: the SPA is built at repo time (npm run build) and
	# shipped in-tree as webui/dist. The daemon serves it from
	# /usr/share/balansir/webui when BALANSIR_WEBUI_DIR is set (systemd unit).
	# Remove the previous set first so hashed asset filenames from an older
	# build never linger (a stale index.html/assets mismatch renders a blank
	# page).
	rm -rf $(TARGET_DIR)/usr/share/balansir/webui
	mkdir -p $(TARGET_DIR)/usr/share/balansir/webui
	cp -a $(BALANSIR_SRCDIR)/webui/dist/. $(TARGET_DIR)/usr/share/balansir/webui/
endef

# Runtime dependencies on the target: nft (executor mechanism) and iproute2.
BALANSIR_DEPENDENCIES = nftables iproute2

$(eval $(cargo-package))
