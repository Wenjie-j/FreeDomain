#!/usr/bin/env python3
"""Read-only audit of a local private UI package against its reviewed staging tree.

Only aggregate status is printed. Neither source code nor package bytes are uploaded.
This is not an OpenWrt package build or target runtime check.
"""

import argparse
import hashlib
import json
from pathlib import Path

from prepare_private_ui_package import MAKEFILE, REQUIRED

PORT_FLAGS = (
    "candidate_controller_method_hardened", "candidate_status_ported",
    "candidate_setup_ported", "candidate_setup_dns_owner_hardened",
    "candidate_manager_rollback_hardened", "candidate_manager_stop_checked",
)


def _regular(path: Path) -> bytes:
    if (path.is_symlink() or any(parent.is_symlink() for parent in path.parents)
            or not path.is_file()):
        raise ValueError("private package path is missing or symlinked")
    return path.read_bytes()


def inspect(staged: Path, package: Path) -> dict:
    for root in (staged, package):
        if (root.is_symlink() or not root.is_dir()
                or any(parent.is_symlink() for parent in root.parents)
                or root.stat().st_mode & 0o077):
            raise ValueError("private source or package directory is not restricted")
    staged_manifest = json.loads(_regular(staged / "OFFLINE-ONLY.json"))
    package_manifest = json.loads(_regular(package / "PRIVATE-PACKAGE.json"))
    digests = staged_manifest.get("staged_file_sha256")
    if (staged_manifest.get("classification") !=
            "PRIVATE_OFFLINE_UI_SOURCE_NOT_INSTALL_APPROVAL"
            or any(staged_manifest.get(flag) is not True for flag in PORT_FLAGS)
            or not isinstance(digests, dict) or set(digests) != set(REQUIRED)
            or package_manifest.get("classification") !=
            "PRIVATE_LOCAL_TEST_PACKAGE_NOT_IMAGE_OR_FLASH_APPROVAL"
            or package_manifest.get("package") != "arthur-singbox-ui-private"
            or package_manifest.get("packaged_paths") != list(REQUIRED)
            or package_manifest.get("packaged_file_sha256") != digests
            or package_manifest.get("contains_config_or_nodes") is not False
            or package_manifest.get("automatic_firewall_activation_added") is not False
            or package_manifest.get("archive_sha256") != staged_manifest.get("archive_sha256")
            or package_manifest.get("services_archive_sha256") !=
            staged_manifest.get("services_archive_sha256")):
        raise ValueError("private source and package manifests disagree")
    expected = {"Makefile", "PRIVATE-PACKAGE.json", *("files/" + x for x in REQUIRED)}
    actual = {p.relative_to(package).as_posix() for p in package.rglob("*") if not p.is_dir()}
    if actual != expected or any(p.is_symlink() for p in package.rglob("*")):
        raise ValueError("unexpected private package payload")
    if _regular(package / "Makefile") != MAKEFILE.encode():
        raise ValueError("private package recipe differs from reviewed template")
    for name in REQUIRED:
        original = _regular(staged / name)
        installed = _regular(package / "files" / name)
        if (not isinstance(digests[name], str) or len(digests[name]) != 64
                or hashlib.sha256(original).hexdigest() != digests[name]
                or original != installed):
            raise ValueError("private staged and packaged source differ")
        mode = (package / "files" / name).stat().st_mode & 0o777
        if mode != (0o700 if name.startswith("etc/init.d/") else 0o600):
            raise ValueError("private package file permissions differ")
    return {
        "classification": "PRIVATE_UI_OFFLINE_PACKAGE_AUDIT_NOT_TARGET_BUILD",
        "status": "SOURCE_AND_PACKAGE_BYTES_MATCH",
        "reviewed_file_count": len(REQUIRED),
        "private_configuration_included": False,
        "target_package_built": False,
        "router_runtime_checked": False,
        "firmware_inclusion_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.staged, args.package), indent=2))


if __name__ == "__main__":
    main()
