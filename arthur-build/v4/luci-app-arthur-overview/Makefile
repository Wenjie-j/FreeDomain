include $(TOPDIR)/rules.mk

PKG_VERSION:=0.1
PKG_RELEASE:=1
LUCI_TITLE:=Arthur V4 status and guided feature entry
LUCI_DEPENDS:=+luci-base +luci-mod-network +luci-mod-status +luci-app-mwan3
LUCI_PKGARCH:=all
# Keep the small status view byte-identical for installed-payload auditing.
LUCI_MINIFY_JS:=0
PKG_LICENSE:=Apache-2.0

include $(TOPDIR)/feeds/luci/luci.mk
# call BuildPackage - OpenWrt package scanner marker for external LuCI packages
