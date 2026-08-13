################################################################################
#
# balansir
#
# Builds the BalanSir network policy engine from the workspace: the daemon
# crate produces balansir-daemon + balansir-cli ([[bin]]), the executor crate
# produces balansir-executor. cargo-package vendoring runs at the workspace
# root (Cargo.lock committed); the build targets the daemon crate manifest,
# which builds the whole dependency graph incl. the executor crate.
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

# cargo-package auto-runs `cargo build --offline --locked --bins` in the
# source dir; point it at the daemon crate manifest so it builds the daemon,
# the CLI and (via the workspace dependency graph) the executor crate.
BALANSIR_CARGO_BUILD_OPTS = --manifest-path crates/balansir-daemon/Cargo.toml
BALANSIR_CARGO_INSTALL_OPTS = --manifest-path crates/balansir-daemon/Cargo.toml

# Runtime dependencies on the target: nft (executor mechanism) and iproute2.
BALANSIR_DEPENDENCIES = nftables iproute2

$(eval $(cargo-package))
