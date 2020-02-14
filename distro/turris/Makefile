# Copyright (C) 2015-2019 CZ.NIC, z. s. p. o. (https://www.nic.cz/)
# SPDX-License-Identifier: GPL-2.0

PKG_RELRO_FULL:=0

include $(TOPDIR)/rules.mk

PKG_NAME:=knot-resolver
PKG_VERSION:=__VERSION__
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER:=Knot DNS <knot-dns@labs.nic.cz>
PKG_LICENSE:=GPL-3.0

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/knot-resolver
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=IP Addresses and Names
	TITLE:=Knot DNS Resolver
	URL:=https://gitlab.labs.nic.cz/knot/resolver
	DEPENDS=+knot-libs +knot-libzscanner +libuv +luajit +dnssec-rootkey +resolver-conf +libstdcpp
	PROVIDES:=dns-resolver
endef

define Package/knot-resolver/description
  The Knot DNS Resolver is a minimalistic caching resolver implementation.
endef

MAKE_FLAGS += \
	PREFIX=/usr \
	ETCDIR=/etc/kresd

define Build/Patch
	$(Build/Patch/Default)
	cd $(PKG_BUILD_DIR) && \
	sed -i -e 's/\(.*find_lib,hiredis.*\)/HAS_hiredis := no/' \
	       -e 's/\(.*find_lib,libmemcached.*\)/HAS_libmemcached := no/' Makefile
endef

define Package/knot-resolver/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/*bin/kresd $(1)/usr/bin/

	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/libkres.so* $(1)/usr/lib
	$(CP) $(PKG_INSTALL_DIR)/usr/lib/kdns_modules $(1)/usr/lib

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/kresd.init $(1)/etc/init.d/kresd

	$(INSTALL_DIR) $(1)/etc/kresd
	$(CP) $(PKG_BUILD_DIR)/etc/icann-ca.pem $(1)/etc/kresd
	$(CP) $(PKG_BUILD_DIR)/etc/root.hints $(1)/etc/kresd
	$(INSTALL_BIN) ./files/kresd.postinst $(1)/etc/kresd/kresd.postinst.sh
	$(INSTALL_BIN) ./files/convert_config.sh $(1)/etc/kresd/convert_config.sh
endef

define Package/$(PKG_NAME)/postinst
#!/bin/sh
set -x
if [ -z "$$IPKG_INSTROOT" ]; then
/etc/init.d/dnsmasq restart
sleep 2 # Cooldown for above (problems in times of reinstall)
/etc/kresd/kresd.postinst.sh && rm /etc/kresd/kresd.postinst.sh
/etc/kresd/convert_config.sh && rm /etc/kresd/convert_config.sh
if [ "`uci -q get resolver.common.prefered_resolver`" = kresd ] && uci -q get resolver.common.forward_upstream | egrep -q '(1|yes|true|enabled|on)'; then
	ping -c 1 api.turris.cz 2> /dev/null >&2 || {
		uci set resolver.common.forward_upstream=0
		uci commit
		/etc/init.d/resolver restart
		if ping -c 1 api.turris.cz 2> /dev/null >&2; then
			create_notification -s error "DNS servery vašeho poskytovatele internetu nefungují úplně dobře - pravděpodobně nepodporují DNSSEC. Bylo proto vypnuto forwardování a váš router bude nyní vyhodnocovat DNS dotazy sám." "Your ISPs DNS servers does not work properly - most likely they don't support DNSSEC. Therefore DNS forwarding was turned off and your router will now resolve all DNS queries by itself."
		else
			uci set resolver.common.forward_upstream=1
			uci commit
			/etc/init.d/resolver restart
		fi
	}
fi
fi
endef

define Package/$(PKG_NAME)/prerm
#!/bin/sh
set -ex
if [ -z "$$IPKG_INSTROOT" ]; then
# Remove the script if it is there.
if [ -e /etc/init.d/kresd ] ; then /etc/init.d/kresd stop ; /etc/init.d/kresd disable ;  fi
fi
endef

define Package/knot-resolver/postrm
#!/bin/sh
if [ -z "$$IPKG_INSTROOT" ]; then
[ \! -x /etc/init.d/resolver ] || /etc/init.d/resolver restart
fi
endef

$(eval $(call BuildPackage,knot-resolver))

