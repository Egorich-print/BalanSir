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
# The workspace root is a virtual manifest, so vendoring runs at the root
# (Cargo.lock committed) and --workspace resolves all crates.
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

# Runtime dependencies on the target: nft (executor mechanism) and iproute2.
BALANSIR_DEPENDENCIES = nftables iproute2

$(eval $(cargo-package))
