#!/usr/bin/env python3
"""Audit the pinned OpenClash package payload and extend file ownership evidence."""

import argparse
import hashlib
import json
import re
from pathlib import Path


PACKAGE = "luci-app-openclash"
EXPECTED_SOURCE = "c3a33c1d3407956fdf8f0e0b7c1a4c52e6ad9593"
REQUIRED_FILES = (
    "etc/config/openclash",
    "etc/init.d/openclash",
    "etc/uci-defaults/luci-openclash",
    "usr/lib/lua/luci/controller/openclash.lua",
    "usr/lib/lua/luci/model/cbi/openclash/config.lua",
    "usr/share/openclash/openclash.sh",
)
PROTECTED_FILES = (
    "usr/bin/sing-box",
    "usr/bin/sing-box-firewall4",
    "usr/share/arthur-v4/firewall4-test-only",
)


def build_report(package_root: Path, apk: Path, config: Path,
                 owners: dict, source_lock: dict) -> tuple[dict, dict]:
    if package_root.is_symlink() or not package_root.is_dir():
        raise ValueError("missing or symlinked OpenClash package root")
    paths = list(package_root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ValueError("OpenClash package payload contains a symlink")
    files = sorted(path.relative_to(package_root).as_posix()
                   for path in paths if path.is_file())
    missing = sorted(set(REQUIRED_FILES) - set(files))
    if missing:
        raise ValueError("OpenClash payload missing required files: " + ", ".join(missing))
    collisions = sorted(set(files) & set(owners))
    protected = sorted(set(files) & set(PROTECTED_FILES))
    if collisions or protected:
        raise ValueError("OpenClash package file collision: " + ", ".join(collisions + protected))
    flags = set(config.read_text(encoding="utf-8").splitlines())
    if "CONFIG_PACKAGE_luci-app-openclash=y" not in flags:
        raise ValueError("OpenClash must be selected in the candidate image config")
    source = source_lock.get("openclash_source", {})
    if (source.get("revision") != EXPECTED_SOURCE
            or source.get("repository") != "https://github.com/vernesong/OpenClash.git"
            or source.get("package_path") != PACKAGE):
        raise ValueError("OpenClash source lock differs from reviewed candidate")
    if (not apk.is_file()
            or not re.fullmatch(r"luci-app-openclash-[A-Za-z0-9._+-]+\.apk", apk.name)):
        raise ValueError("expected OpenClash APK missing")
    defaults = (package_root / "etc/uci-defaults/luci-openclash").read_text(
        encoding="utf-8", errors="strict")
    preserves_config = all(token in defaults for token in (
        "/lib/upgrade/keep.d/luci-app-openclash", "/etc/openclash/"))
    if not preserves_config:
        raise ValueError("OpenClash payload lacks its sysupgrade preservation declaration")
    merged = {path: list(packages) for path, packages in owners.items()}
    for name in files:
        merged[name] = [PACKAGE]
    report = {
        "classification": "OPENCLASH_PACKAGE_BUILD_NOT_RUNTIME_OR_MIGRATION_APPROVAL",
        "package": PACKAGE,
        "source_commit": EXPECTED_SOURCE,
        "package_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "installed_file_count": len(files),
        "required_luci_and_service_files_present": True,
        "sysupgrade_config_preservation_declared": True,
        "protected_backend_file_collisions": [],
        "runtime_firewall_dns_nss_interaction_tested": False,
        "status": "PACKAGE_PAYLOAD_AUDITED",
    }
    return report, merged


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", required=True, type=Path)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--owners", required=True, type=Path)
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    report, owners = build_report(
        args.package_root, args.apk, args.config,
        json.loads(args.owners.read_text(encoding="utf-8")),
        json.loads(args.source_lock.read_text(encoding="utf-8")),
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "v4-openclash-package-build.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "v4-package-file-owners.partial.json").write_text(
        json.dumps(owners, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
