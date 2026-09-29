#!/usr/bin/env python3
"""Validate the non-activating Arthur firewall4 test package layout."""

import argparse
import json
from pathlib import Path


REQUIRED_DEPENDS = ("+firewall4", "+ip-full", "+kmod-nft-tproxy")


def validate(package: Path, candidate: Path) -> dict:
    makefile = (package / "Makefile").read_text()
    installed = package / "files/sing-box-firewall4"
    note = package / "files/TEST-ONLY"
    checks = {
        "package_arch_all": "PKGARCH:=all" in makefile,
        "dependencies_declared": all(item in makefile for item in REQUIRED_DEPENDS),
        "installs_expected_binary":
            "$(1)/usr/bin/sing-box-firewall4" in makefile,
        "no_init_script_packaged": not (package / "files/etc/init.d").exists(),
        "no_generated_nft_rules_packaged": not any(
            package.glob("files/**/*.nft")),
        "candidate_bytes_match": installed.read_bytes() == candidate.read_bytes(),
        "candidate_is_executable": bool(installed.stat().st_mode & 0o111),
        "test_only_notice": note.is_file() and "No automatic activation" in note.read_text(),
    }
    return {
        "classification": "TEST_PACKAGE_LAYOUT_ONLY_NOT_IMAGE_OR_FLASH_APPROVAL",
        "package": "arthur-singbox-firewall4-test",
        "checks": checks,
        "status": "PASS_LAYOUT_ONLY" if all(checks.values()) else "BLOCKED_LAYOUT",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    report = validate(args.package, args.candidate)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "PASS_LAYOUT_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
