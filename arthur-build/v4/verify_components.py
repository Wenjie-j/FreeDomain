#!/usr/bin/env python3
"""Check V4 build contents offline. Passing is never permission to flash."""
import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path

REQUIRED_PACKAGES = {
    "base": ("luci", "luci-i18n-base-zh-cn", "luci-compat", "firewall4"),
    "familiar_ui": ("luci-theme-argon",),
    "proxy": ("sing-box", "kmod-tun", "kmod-nft-tproxy", "luci-app-openclash"),
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
    "etc/init.d/sing-box-setup",
    "usr/lib/lua/luci/model/cbi/singbox_status.lua",
    "usr/bin/sing-box-firewall4",
    "usr/bin/sing-box",
    "etc/openclash/core/clash_meta",
)
CORE_TAGS = {"with_quic", "with_dhcp", "with_wireguard", "with_utls", "with_clash_api"}
CUSTOM_OWNED_FILES = (
    "etc/init.d/sing-box", "etc/init.d/sing-box-setup",
    "usr/lib/lua/luci/controller/singbox.lua",
    "usr/lib/lua/luci/view/singbox/nodes.htm",
    "usr/lib/lua/singbox/manager.lua",
    "usr/lib/lua/luci/model/cbi/singbox_status.lua",
    "usr/bin/sing-box-firewall4",
)
CORE_FORBIDDEN_FILES = (
    "etc/config/sing-box", "etc/sing-box/config.json", *CUSTOM_OWNED_FILES,
)
V4_BASE = "92a2d104145c8d265851c4b388a41bd8e9c21cd9"
CORE_SOURCE = "1ac1a339cb1223e9c70eae14c44411c75033c02d"
OPENCLASH_CORE_SOURCE = "6b99254c577e4e674887e93f42da89a03b5e9e44"
OPENCLASH_CORE_BLOB = "5c90d325491032c316849c0ed39711a16dfdda4c"
MUTATION_ACTIONS = ("active", "test", "delete", "move", "add_link", "add_raw",
                    "add_manual", "update", "sub_add", "sub_update", "sub_rename",
                    "sub_delete")


def backend_port_checks(root_dir: Path | None) -> dict:
    names = {
        "post_only_mutation_routes": "usr/lib/lua/luci/controller/singbox.lua",
        "setup_uses_ported_firewall": "etc/init.d/sing-box-setup",
        "status_avoids_legacy_iptables": "usr/lib/lua/luci/model/cbi/singbox_status.lua",
        "firewall4_replaces_legacy_commands": "usr/bin/sing-box-firewall4",
    }


    if root_dir is None:
        return {key: "NOT_INSPECTED" for key in names}
    content = {}
    for key, name in names.items():
        path = root_dir / name
        content[key] = path.read_text(errors="replace") if path.is_file() else ""
    controller = content["post_only_mutation_routes"]
    setup = content["setup_uses_ported_firewall"]
    status = content["status_avoids_legacy_iptables"]
    firewall = content["firewall4_replaces_legacy_commands"]
    return {
        "post_only_mutation_routes": all(
            bool(re.search(r'\bpost\("api_' + action + r'"\)', controller))
            and 'call("api_' + action + '")' not in controller
            for action in MUTATION_ACTIONS
        ),
        "setup_uses_ported_firewall": "/usr/bin/sing-box-firewall4 start" in setup
        and "/usr/bin/sing-box-firewall start" not in setup,
        "status_avoids_legacy_iptables": bool(status) and "iptables" not in status,
        "firewall4_replaces_legacy_commands": bool(firewall)
        and "nft" in firewall
        and not any(x in firewall for x in ("iptables", "ip6tables", "ipset"))
        and not re.search(r'(?m)^\s*(?:HY2_IP|SERVER_IP)\s*=\s*["\x27]\d', firewall),
    }


def package_ownership_checks(owners: dict | None) -> dict:
    """Read an explicit build-package file list, not a root-file guess."""
    if owners is None:
        return {"core_binary_owned_by_core": "NOT_INSPECTED",
                "custom_files_not_owned_by_core": "NOT_INSPECTED",
                "custom_files_have_separate_owner": "NOT_INSPECTED",
                "openclash_core_owned_separately": "NOT_INSPECTED"}
    if not isinstance(owners, dict) or any(
        not isinstance(path, str) or not isinstance(packages, list)
        or not packages or not all(isinstance(pkg, str) and pkg for pkg in packages)
        for path, packages in owners.items()
    ):
        raise ValueError("invalid package file ownership report")
    def owner_set(path):
        return set(owners.get(path, []))
    return {
        "core_binary_owned_by_core": owner_set("usr/bin/sing-box") == {"sing-box"},
        "custom_files_not_owned_by_core": all(
            "sing-box" not in owner_set(path) for path in CORE_FORBIDDEN_FILES),
        "custom_files_have_separate_owner": all(
            len(owner_set(path)) == 1 and "sing-box" not in owner_set(path)
            for path in CUSTOM_OWNED_FILES),
        "openclash_core_owned_separately": (
            owner_set("etc/openclash/core/clash_meta") == {"arthur-openclash-core"}),
    }


def inspect(artifact: Path, root_dir: Path | None = None,
            core_build_report: dict | None = None,
            package_file_owners: dict | None = None,
            openclash_core_build_report: dict | None = None) -> dict:
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
    backend_checks = backend_port_checks(root_dir)
    ownership_checks = package_ownership_checks(package_file_owners)
    # A copied Linux 4.4 binary can have the same name and version as a V4 build.
    # This only checks declared build trace + byte identity, not hardware runtime.
    core_trace = "MISSING_V4_BUILD_TRACE"
    if root_dir is not None and isinstance(core_build_report, dict):
        binary = root_dir / "usr/bin/sing-box"
        if binary.is_file() and all((
            core_build_report.get("base_commit") == V4_BASE,
            core_build_report.get("source_commit") == CORE_SOURCE,
            core_build_report.get("source_version") == "1.14.1",
            core_build_report.get("target_arch_packages") == "aarch64_cortex-a53",
            isinstance(core_build_report.get("build_tags"), list),
        )):
            tags = core_build_report["build_tags"]
            if (all(isinstance(tag, str) for tag in tags)
                    and CORE_TAGS.issubset(tags)
                    and hashlib.sha256(binary.read_bytes()).hexdigest()
                    == core_build_report.get("binary_sha256")):
                core_trace = "MATCHES_DECLARED_V4_BUILD_TRACE"
        if core_trace != "MATCHES_DECLARED_V4_BUILD_TRACE":
            core_trace = "INVALID_V4_BUILD_TRACE"
    # OpenClash's LuCI APK does not include the separate ARM64 proxy core.
    # Verify staged bytes and a pinned, declared source trace independently.
    openclash_trace = "MISSING_OPENCLASH_CORE_TRACE"
    if root_dir is not None and isinstance(openclash_core_build_report, dict):
        binary = root_dir / "etc/openclash/core/clash_meta"
        if binary.is_file():
            data = binary.read_bytes()
            if (len(data) >= 20 and data[:6] == b"\x7fELF\x02\x01"
                    and data[18:20] == b"\xb7\x00"
                    and openclash_core_build_report.get("source_repository")
                    == "https://github.com/vernesong/OpenClash.git"
                    and openclash_core_build_report.get("source_commit")
                    == OPENCLASH_CORE_SOURCE
                    and openclash_core_build_report.get("source_blob_sha")
                    == OPENCLASH_CORE_BLOB
                    and openclash_core_build_report.get("target_arch") == "aarch64"
                    and openclash_core_build_report.get("binary_sha256")
                    == hashlib.sha256(data).hexdigest()):
                openclash_trace = "MATCHES_DECLARED_OPENCLASH_CORE_TRACE"
        if openclash_trace != "MATCHES_DECLARED_OPENCLASH_CORE_TRACE":
            openclash_trace = "INVALID_OPENCLASH_CORE_TRACE"
    complete = (not missing and all(flags.values())
                and all(x is True for x in root_files.values())
                and all(x is True for x in backend_checks.values())
                and all(x is True for x in ownership_checks.values())
                and core_trace == "MATCHES_DECLARED_V4_BUILD_TRACE"
                and openclash_trace == "MATCHES_DECLARED_OPENCLASH_CORE_TRACE")
    return {
        "classification": "COMPONENT_INVENTORY_ONLY_NOT_FLASH_APPROVAL",
        "artifact": artifact.name,
        "missing_packages": missing,
        "build_flags": flags,
        "staged_root_files": root_files,
        "backend_port_checks": backend_checks,
        "package_file_ownership": ownership_checks,
        "core_build_trace": core_trace,
        "openclash_core_trace": openclash_trace,
        "component_gate": "COMPONENTS_PRESENT" if complete else "BLOCKED_INCOMPLETE_COMPONENTS",
        "release_note": "Boot, config migration, recovery and interactive UI still require separate validation.",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--artifact", required=True, type=Path)
    ap.add_argument("--root-dir", type=Path)
    ap.add_argument("--core-build-report", type=Path,
                    help="Metadata from a new V4 toolchain build; never the old router binary")
    ap.add_argument("--package-file-owners", type=Path,
                    help="Build package file lists as JSON path-to-package arrays")
    ap.add_argument("--openclash-core-build-report", type=Path,
                    help="Declared pinned ARM64 OpenClash core provenance and staged binary SHA-256")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args(argv)
    try:
        core_build_report = (json.loads(args.core_build_report.read_text(encoding="utf-8"))
                             if args.core_build_report else None)
        package_file_owners = (json.loads(args.package_file_owners.read_text(encoding="utf-8"))
                               if args.package_file_owners else None)
        openclash_core_build_report = (
            json.loads(args.openclash_core_build_report.read_text(encoding="utf-8"))
            if args.openclash_core_build_report else None)
        report = inspect(args.artifact, args.root_dir, core_build_report,
                         package_file_owners, openclash_core_build_report)
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
