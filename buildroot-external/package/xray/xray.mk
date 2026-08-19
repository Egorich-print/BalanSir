################################################################################
#
# xray-core
#
################################################################################

XRAY_CORE_VERSION = 26.7.28
XRAY_CORE_SITE = $(call github,XTLS,Xray-core,v$(XRAY_CORE_VERSION))
XRAY_CORE_LICENSE = GPL-3.0
XRAY_CORE_LICENSE_FILES = LICENSE
XRAY_CORE_GOMOD = github.com/XTLS/Xray-core
XRAY_CORE_BUILD_TARGETS = main
XRAY_CORE_LDFLAGS = -s -w
XRAY_CORE_INSTALL_BINS = xray

$(eval $(golang-package))