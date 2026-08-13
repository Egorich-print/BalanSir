################################################################################
#
# btop
#
################################################################################

BTOP_VERSION = 1.4.7
BTOP_SITE = $(call github,aristocratos,btop,v$(BTOP_VERSION))
BTOP_LICENSE = Apache-2.0
BTOP_LICENSE_FILES = LICENSE
BTOP_DEPENDENCIES = host-cmake

# btop forbids in-source builds (its CMakeLists errors on them); must be set
# before $(eval $(cmake-package)) so pkg-cmake picks it up.
BTOP_SUPPORTS_IN_SOURCE_BUILD = NO

$(eval $(cmake-package))
