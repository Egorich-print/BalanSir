# BalanSir external tree makefile
#
# The balansir package is defined in package/balansir/balansir.mk.

include $(sort $(wildcard $(BR2_EXTERNAL_BALANSIR_PATH)/package/*/*.mk))

# --- Tailscale daemon ELF fix ----------------------------------------------
# Buildroot 2026.05's golang-package installs only `/usr/bin/tailscale` and
# creates self-referential `tailscaled -> ../bin/tailscaled` symlinks (a loop),
# so the unit's ExecStart fails 203/EXEC and tailscaled restart-loops every
# 100ms (pinning CPU, starving systemd, blocking networkd on first boot).
# The real daemon ELF is built at $(TAILSCALE_DIR)/bin/tailscaled but never
# installed; copy it here and repoint the symlinks.
define BALANSIR_TAILSCALED_FIX
	rm -f $(TARGET_DIR)/usr/bin/tailscaled $(TARGET_DIR)/usr/sbin/tailscaled $(TARGET_DIR)/bin/tailscaled
	$(INSTALL) -D -m 0755 $(TAILSCALE_DIR)/bin/tailscaled $(TARGET_DIR)/usr/bin/tailscaled
	ln -sf /usr/bin/tailscaled $(TARGET_DIR)/usr/sbin/tailscaled
	ln -sf /usr/bin/tailscaled $(TARGET_DIR)/bin/tailscaled
endef
TAILSCALE_POST_INSTALL_TARGET_HOOKS += BALANSIR_TAILSCALED_FIX
