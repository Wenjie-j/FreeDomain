#!/usr/bin/env python3
"""Turn a reviewed private UI staging tree into a local OpenWrt package."""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path


REQUIRED = (
    "usr/lib/lua/luci/controller/singbox.lua",
    "usr/lib/lua/luci/view/singbox/nodes.htm",
    "usr/lib/lua/luci/model/cbi/singbox_status.lua",
    "usr/lib/lua/singbox/manager.lua",
    "etc/init.d/sing-box",
    "etc/init.d/sing-box-setup",
)

MAKEFILE = r'''include $(TOPDIR)/rules.mk

PKG_NAME:=arthur-singbox-ui-private
PKG_VERSION:=0.1
PKG_RELEASE:=1
PKGARCH:=all
PKG_LICENSE:=Private-source

include $(INCLUDE_DIR)/package.mk

define Package/arthur-singbox-ui-private
  SECTION:=luci
  CATEGORY:=LuCI
  TITLE:=Arthur private Sing-box UI and services
  DEPENDS:=+luci +luci-compat +curl +sing-box +arthur-singbox-firewall4-test
endef

define Package/arthur-singbox-ui-private/description
  Private source-only port of the existing Arthur Sing-box UI and services.
endef

define Build/Compile
endef

define Package/arthur-singbox-ui-private/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/controller/singbox.lua $(1)/usr/lib/lua/luci/controller/singbox.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/singbox
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/view/singbox/nodes.htm $(1)/usr/lib/lua/luci/view/singbox/nodes.htm
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DATA) ./files/usr/lib/lua/luci/model/cbi/singbox_status.lua $(1)/usr/lib/lua/luci/model/cbi/singbox_status.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/singbox
	$(INSTALL_DATA) ./files/usr/lib/lua/singbox/manager.lua $(1)/usr/lib/lua/singbox/manager.lua
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/sing-box $(1)/etc/init.d/sing-box
	$(INSTALL_BIN) ./files/etc/init.d/sing-box-setup $(1)/etc/init.d/sing-box-setup
endef

$(eval $(call BuildPackage,arthur-singbox-ui-private))
'''


def prepare(staged: Path, output: Path) -> dict:
    if staged.is_symlink() or not staged.is_dir():
        raise ValueError("private staging root must be a regular directory")
    manifest_path = staged / "OFFLINE-ONLY.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError("private staging manifest missing or symlinked")
    manifest = json.loads(manifest_path.read_text())
    flags = ("candidate_controller_method_hardened", "candidate_status_ported",
             "candidate_setup_ported", "candidate_setup_dns_owner_hardened",
             "candidate_manager_rollback_hardened")
    if (manifest.get("classification") != "PRIVATE_OFFLINE_UI_SOURCE_NOT_INSTALL_APPROVAL"
            or any(manifest.get(flag) is not True for flag in flags)):
        raise ValueError("private staging tree has not passed required ports")
    digests = manifest.get("staged_file_sha256")
    if (not isinstance(digests, dict) or set(digests) != set(REQUIRED)
            or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                   for value in digests.values())):
        raise ValueError("private staging digest manifest incomplete")
    if output.is_symlink() or (output.exists()
                              and (not output.is_dir() or any(output.iterdir()))):
        raise ValueError("package output directory must be empty")
    sources = {}
    for name in REQUIRED:
        path = staged / name
        if (not path.is_file()
                or any((staged / Path(*Path(name).parts[:index])).is_symlink()
                       for index in range(1, len(Path(name).parts) + 1))):
            raise ValueError("private staging file missing or symlinked")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digests[name]:
            raise ValueError("private staging file differs from prepared source")
        sources[name] = data
    output.mkdir(parents=True, exist_ok=True)
    os.chmod(output, 0o700)
    (output / "Makefile").write_text(MAKEFILE)
    for name in REQUIRED:
        target = output / "files" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(sources[name])
        target.chmod(0o700 if name.startswith("etc/init.d/") else 0o600)
    report = {
        "classification": "PRIVATE_LOCAL_TEST_PACKAGE_NOT_IMAGE_OR_FLASH_APPROVAL",
        "package": "arthur-singbox-ui-private",
        "packaged_paths": list(REQUIRED),
        "packaged_file_sha256": digests,
        "archive_sha256": manifest.get("archive_sha256"),
        "services_archive_sha256": manifest.get("services_archive_sha256"),
        "contains_config_or_nodes": False,
        "automatic_firewall_activation_added": False,
    }
    (output / "PRIVATE-PACKAGE.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.staged, args.output), indent=2))


if __name__ == "__main__":
    main()
