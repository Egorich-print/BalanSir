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

XRAY_VERSION = 26.7.28
XRAY_SOURCE = Xray-linux-arm64-v8a.zip
XRAY_SITE = https://github.com/XTLS/Xray-core/releases/download/v$(XRAY_VERSION)
XRAY_LICENSE = GPL-3.0
XRAY_LICENSE_FILES = LICENSE

define XRAY_EXTRACT_CMDS
	$(UNZIP) -o $(XRAY_DL_DIR)/$(XRAY_SOURCE) -d $(@D)
endef

define XRAY_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/xray $(TARGET_DIR)/usr/bin/xray
endef

$(eval $(generic-package))
