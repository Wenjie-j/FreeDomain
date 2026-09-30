#!/usr/bin/env python3
"""Audit the independent OpenClash core payload without starting the proxy."""
import argparse
import hashlib
import json
import re
from pathlib import Path

from prepare_openclash_core import ARCHIVE_PATH, BLOB, REPOSITORY, SOURCE, validate_arm64_elf

PACKAGE = "arthur-openclash-core"
CORE_PATH = "etc/openclash/core/clash_meta"


def build_report(root: Path, apk: Path, config: Path,
                 owners: dict, trace: dict) -> tuple[dict, dict]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("missing or symlinked core package root")
    paths = list(root.rglob("*"))
    if any(path.is_symlink() for path in paths):
        raise ValueError("core payload contains a symlink")
    files = [path.relative_to(root).as_posix() for path in paths if path.is_file()]
    if files != [CORE_PATH] or CORE_PATH in owners:
        raise ValueError("core payload must own only its separate, unclaimed executable")
    binary = root / CORE_PATH
    data = binary.read_bytes()
    validate_arm64_elf(data)
    if not binary.stat().st_mode & 0o111:
        raise ValueError("staged core is not executable")
    expected = {
        "source_repository": REPOSITORY, "source_commit": SOURCE,
        "source_archive_path": ARCHIVE_PATH, "source_blob_sha": BLOB,
        "archive_git_blob_verified": True, "target_arch": "aarch64",
        "binary_sha256": hashlib.sha256(data).hexdigest(), "binary_size": len(data),
        "executed_during_preparation": False,
    }
    if (any(trace.get(key) != value for key, value in expected.items())
            or not re.fullmatch(r"[0-9a-f]{64}", str(trace.get("archive_sha256", "")))):
        raise ValueError("core preparation trace differs from staged payload")
    if "CONFIG_PACKAGE_arthur-openclash-core=m" not in config.read_text().splitlines():
        raise ValueError("prebuilt trial core must be a module outside the candidate image")
    if not apk.is_file() or not re.fullmatch(r"arthur-openclash-core-[A-Za-z0-9._+-]+\.apk", apk.name):
        raise ValueError("expected core APK missing")
    merged = {path: list(packages) for path, packages in owners.items()}
    merged[CORE_PATH] = [PACKAGE]
    return {
        "classification": "OPENCLASH_CORE_PACKAGE_NOT_RUNTIME_APPROVAL",
        "package": PACKAGE, "package_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "binary_sha256": expected["binary_sha256"], "target_arch": "aarch64",
        "installed_file_count": 1, "configuration_or_service_installed": False,
        "image_inclusion_approved": False,
        "runtime_tested": False, "status": "PACKAGE_PAYLOAD_AUDITED",
    }, merged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package-root", "apk", "config", "owners", "trace", "output-dir"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    report, owners = build_report(args.package_root, args.apk, args.config,
                                 json.loads(args.owners.read_text()),
                                 json.loads(args.trace.read_text()))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "v4-openclash-core-package-build.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "v4-package-file-owners.partial.json").write_text(
        json.dumps(owners, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
