#!/usr/bin/env python3
"""Check V4 build contents offline. Passing is never permission to flash."""
import argparse
import json
import sys
import zipfile
from pathlib import Path

REQUIRED_PACKAGES = {
    "base": ("luci", "luci-i18n-base-zh-cn", "luci-compat", "firewall4"),
    "familiar_ui": ("luci-theme-argon",),
    "proxy": ("sing-box", "kmod-tun", "luci-app-openclash"),
    "multi_wan": ("mwan3", "luci-app-mwan3"),
    "radio": ("kmod-ath11k", "wpad-mesh-openssl"),
    "nss": ("kmod-qca-nss-dp", "kmod-qca-nss-drv", "kmod-qca-nss-ecm",
            "nss-firmware-ipq60xx"),
}

REQUIRED_ROOT_FILES = (
    "usr/lib/lua/luci/controller/singbox.lua",
    "usr/lib/lua/luci/view/singbox/nodes.htm",
    "usr/lib/lua/singbox/manager.lua",
    "etc/init.d/sing-box",
    "usr/bin/sing-box",
)


def inspect(artifact: Path, root_dir: Path | None = None) -> dict:
    with zipfile.ZipFile(artifact) as z:
        manifests = [n for n in z.namelist() if n.endswith("jdcloud_re-ss-01.manifest")]
        if len(manifests) != 1 or "final.config" not in z.namelist():
            raise ValueError("expected one Arthur package manifest and final.config")
        packages = {line.partition(" - ")[0]
                    for line in z.read(manifests[0]).decode("utf-8").splitlines()}
        config = z.read("final.config").decode("utf-8")
    missing = {name: sorted(set(group) - packages)
               for name, group in REQUIRED_PACKAGES.items()}
    missing = {name: items for name, items in missing.items() if items}
    flags = {
        "target_re_ss_01": "CONFIG_TARGET_qualcommax_ipq60xx_DEVICE_jdcloud_re-ss-01=y" in config,
        "ath11k_1g_profile": "CONFIG_ATH11K_MEM_PROFILE_1G=y" in config,
        "simplified_chinese": "CONFIG_LUCI_LANG_zh_Hans=y" in config,
        "nss_firmware_11_4": "CONFIG_NSS_FIRMWARE_VERSION_11_4=y" in config,
    }
    if root_dir is None:
        root_files = {p: "NOT_INSPECTED" for p in REQUIRED_ROOT_FILES}
    else:
        root_files = {p: (root_dir / p).is_file() for p in REQUIRED_ROOT_FILES}
    complete = not missing and all(flags.values()) and all(x is True for x in root_files.values())
    return {
        "classification": "COMPONENT_INVENTORY_ONLY_NOT_FLASH_APPROVAL",
        "artifact": artifact.name,
        "missing_packages": missing,
        "build_flags": flags,
        "staged_root_files": root_files,
        "component_gate": "COMPONENTS_PRESENT" if complete else "BLOCKED_INCOMPLETE_COMPONENTS",
        "release_note": "Boot, config migration, recovery and interactive UI still require separate validation.",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--artifact", required=True, type=Path)
    ap.add_argument("--root-dir", type=Path)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args(argv)
    try:
        report = inspect(args.artifact, args.root_dir)
    except (OSError, ValueError, UnicodeError, zipfile.BadZipFile) as exc:
        report = {"classification": "COMPONENT_INVENTORY_ONLY_NOT_FLASH_APPROVAL",
                  "component_gate": "BLOCKED_INVALID_ARTIFACT", "error": str(exc)}
    body = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(body, encoding="utf-8")
    print(body, end="")
    return 0 if report["component_gate"] == "COMPONENTS_PRESENT" else 2


if __name__ == "__main__":
    sys.exit(main())
