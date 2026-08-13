################################################################################
#
# fastfetch
#
################################################################################

FASTFETCH_VERSION = 2.67.0
FASTFETCH_SITE = $(call github,fastfetch-cli,fastfetch,$(FASTFETCH_VERSION))
FASTFETCH_LICENSE = MIT
FASTFETCH_LICENSE_FILES = LICENSE
FASTFETCH_DEPENDENCIES = host-cmake

# fastfetch also uses out-of-source builds; set before $(eval ...).
FASTFETCH_SUPPORTS_IN_SOURCE_BUILD = NO

$(eval $(cmake-package))
