# BalanSir external tree makefile
#
# The balansir package is defined in package/balansir/balansir.mk.

include $(sort $(wildcard $(BR2_EXTERNAL_BALANSIR_PATH)/package/*/*.mk))
