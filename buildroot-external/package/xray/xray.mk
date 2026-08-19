################################################################################
#
# xray-core (prebuilt binary from GitHub Releases)
#
# Xray-core publishes static arm64 binaries; building from Go source in
# Buildroot's golang-package would require vendoring the whole dependency
# tree (GOPROXY is off). A generic-package download of the release zip is
# the lazy correct path.
#
################################################################################

XRAY_CORE_VERSION = 26.7.28
XRAY_CORE_SOURCE = Xray-linux-arm64-v8a.zip
XRAY_CORE_SITE = https://github.com/XTLS/Xray-core/releases/download/v$(XRAY_CORE_VERSION)
XRAY_CORE_LICENSE = GPL-3.0
XRAY_CORE_LICENSE_FILES = LICENSE
XRAY_CORE_DEPENDENCIES = host-unzip

define XRAY_CORE_EXTRACT_CMDS
	$(UNZIP) -o $(XRAY_CORE_DL_DIR)/$(XRAY_CORE_SOURCE) -d $(@D)
endef

define XRAY_CORE_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/xray $(TARGET_DIR)/usr/bin/xray
endef

$(eval $(generic-package))
