#!/usr/bin/env python3
"""Report the built V4 Sing-box core's origin and installed file ownership.

This is package-build evidence, not an image, runtime, or flash approval.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

from verify_components import CORE_SOURCE, CORE_TAGS, V4_BASE

TAG_FLAGS = {
    "with_quic": "CONFIG_SINGBOX_WITH_QUIC",
    "with_dhcp": "CONFIG_SINGBOX_WITH_DHCP",
    "with_wireguard": "CONFIG_SINGBOX_WITH_WIREGUARD",
    "with_utls": "CONFIG_SINGBOX_WITH_UTLS",
    "with_clash_api": "CONFIG_SINGBOX_WITH_CLASH_API",
}
ARCH = "aarch64_cortex-a53"
PACKAGE = "sing-box-1.14.1-r1.apk"


def build_reports(package_root: Path, apk: Path, config: Path) -> tuple[dict, dict, dict]:
    if package_root.is_symlink() or not package_root.is_dir():
        raise ValueError("missing or symlinked package install root")
    files = sorted(p.relative_to(package_root).as_posix()
                   for p in package_root.rglob("*") if p.is_file())
    if files != ["usr/bin/sing-box"] or any(p.is_symlink() for p in package_root.rglob("*")):
        raise ValueError("core package must install only usr/bin/sing-box")
    binary = package_root / "usr/bin/sing-box"
    if not binary.read_bytes().startswith(b"\x7fELF"):
        raise ValueError("core binary is not ELF")
    flags = set(config.read_text(encoding="utf-8").splitlines())
    if ('CONFIG_TARGET_ARCH_PACKAGES="' + ARCH + '"' not in flags
            or "CONFIG_PACKAGE_sing-box=y" not in flags):
        raise ValueError("wrong target architecture or core selection")
    tags = sorted(tag for tag, flag in TAG_FLAGS.items() if flag + "=y" in flags)
    if not CORE_TAGS.issubset(tags):
        raise ValueError("required Sing-box build feature missing")
    if (apk.name != PACKAGE or not apk.is_file()
            or not re.search(r"(?:^|/)bin/packages/" + ARCH + r"/", apk.as_posix())):
        raise ValueError("expected package archive is missing or from wrong architecture")
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    archive_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
    trace = {
        "classification": "CORE_PACKAGE_BUILD_TRACE_NOT_RUNTIME_APPROVAL",
        "base_commit": V4_BASE,
        "source_commit": CORE_SOURCE,
        "source_version": "1.14.1",
        "target_arch_packages": ARCH,
        "build_tags": tags,
        "binary_sha256": binary_hash,
        "package_sha256": archive_hash,
    }
    owners = {"usr/bin/sing-box": ["sing-box"]}
    summary = {
        "classification": "CORE_PACKAGE_ONLY_NOT_FIRMWARE_OR_RUNTIME_APPROVAL",
        "packages": [{"name": PACKAGE, "sha256": archive_hash}],
        "staged_package_files": files,
        "status": "PACKAGE_BUILT",
    }
    return trace, owners, summary


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--package-root", required=True, type=Path)
    ap.add_argument("--apk", required=True, type=Path)
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    args = ap.parse_args()
    trace, owners, summary = build_reports(args.package_root, args.apk, args.config)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, data in (
        ("v4-core-build-trace.json", trace),
        ("v4-core-file-owners.json", owners),
        ("v4-core-package-build.json", summary),
    ):
        (args.output_dir / name).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
