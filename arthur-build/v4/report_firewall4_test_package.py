#!/usr/bin/env python3
"""Report the built, non-activating Arthur firewall4 test package."""

import argparse
import hashlib
import json
import re
from pathlib import Path


PACKAGE = "arthur-singbox-firewall4-test"
EXPECTED_FILES = (
    "usr/bin/sing-box-firewall4",
    "usr/share/arthur-v4/firewall4-test-only",
)


def build_report(package_root: Path, apk: Path, config: Path,
                 candidate: Path, core_owners: dict) -> tuple[dict, dict]:
    if package_root.is_symlink() or not package_root.is_dir():
        raise ValueError("missing or symlinked firewall4 package root")
    paths = list(package_root.rglob("*"))
    files = sorted(p.relative_to(package_root).as_posix() for p in paths if p.is_file())
    if files != sorted(EXPECTED_FILES) or any(path.is_symlink() for path in paths):
        raise ValueError("unexpected firewall4 package contents")
    binary = package_root / EXPECTED_FILES[0]
    if binary.read_bytes() != candidate.read_bytes():
        raise ValueError("packaged backend differs from reviewed candidate")
    if not binary.read_text().startswith("#!/bin/sh\n") or not binary.stat().st_mode & 0o111:
        raise ValueError("packaged backend is not an executable shell script")
    if any(token in binary.read_text() for token in ("iptables", "ip6tables", "ipset")):
        raise ValueError("legacy firewall command found in packaged backend")
    flags = set(config.read_text().splitlines())
    if "CONFIG_PACKAGE_arthur-singbox-firewall4-test=m" not in flags:
        raise ValueError("test backend must be compiled as a module")
    if (not apk.is_file()
            or not re.fullmatch(r"arthur-singbox-firewall4-test-0\.1-r1\.apk", apk.name)):
        raise ValueError("expected firewall4 test APK missing")
    if core_owners != {"usr/bin/sing-box": ["sing-box"]}:
        raise ValueError("unexpected core ownership input")
    archive_hash = hashlib.sha256(apk.read_bytes()).hexdigest()
    owners = dict(core_owners)
    for name in files:
        owners[name] = [PACKAGE]
    report = {
        "classification": "TEST_PACKAGE_BUILD_NOT_IMAGE_OR_RUNTIME_APPROVAL",
        "package": PACKAGE,
        "package_sha256": archive_hash,
        "staged_package_files": files,
        "automatic_activation_packaged": False,
        "generated_nft_rules_packaged": False,
        "status": "TEST_PACKAGE_BUILT",
    }
    return report, owners


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--core-owners", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report, owners = build_report(
        args.package_root, args.apk, args.config, args.candidate,
        json.loads(args.core_owners.read_text()),
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "v4-firewall4-package-build.json").write_text(
        json.dumps(report, indent=2) + "\n")
    (args.output_dir / "v4-package-file-owners.partial.json").write_text(
        json.dumps(owners, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
