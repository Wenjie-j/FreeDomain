include $(TOPDIR)/rules.mk

PKG_NAME:=arthur-openclash-core
PKG_VERSION:=20260930
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0
PKG_MAINTAINER:=Arthur V4 project

include $(INCLUDE_DIR)/package.mk

define Package/arthur-openclash-core
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Pinned ARM64 OpenClash Meta core candidate
  DEPENDS:=@aarch64
endef

define Package/arthur-openclash-core/description
  Independently verified upstream prebuilt ARM64 core candidate for Arthur V4.
  Installs no init script, configuration or automatic activation. Runtime
  compatibility and migration still require separate target validation.
endef

define Build/Compile
endef

define Package/arthur-openclash-core/install
	$(INSTALL_DIR) $(1)/etc/openclash/core
	$(INSTALL_BIN) ./files/clash_meta $(1)/etc/openclash/core/clash_meta
endef

$(eval $(call BuildPackage,arthur-openclash-core))
