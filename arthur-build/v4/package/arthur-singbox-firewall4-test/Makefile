include $(TOPDIR)/rules.mk

PKG_NAME:=arthur-singbox-firewall4-test
PKG_VERSION:=0.1
PKG_RELEASE:=1
PKGARCH:=all

PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=Arthur V4 project

include $(INCLUDE_DIR)/package.mk

define Package/arthur-singbox-firewall4-test
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Arthur Sing-box firewall4 target test backend
  DEPENDS:=+firewall4 +ip-full +kmod-nft-tproxy
endef

define Package/arthur-singbox-firewall4-test/description
  Test-only firewall4 backend for the Arthur V4 integration image. The package
  installs no init script and does not activate transparent proxy rules.
endef

define Build/Compile
endef

define Package/arthur-singbox-firewall4-test/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/sing-box-firewall4 $(1)/usr/bin/sing-box-firewall4
	$(INSTALL_DIR) $(1)/usr/share/arthur-v4
	$(INSTALL_DATA) ./files/TEST-ONLY $(1)/usr/share/arthur-v4/firewall4-test-only
endef

$(eval $(call BuildPackage,arthur-singbox-firewall4-test))
