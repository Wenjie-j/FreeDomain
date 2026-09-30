#!/usr/bin/env python3
"""Validate a private legacy proxy archive without printing secret values."""

import argparse
import hashlib
import json
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_MEMBER = 16 * 1024 * 1024
MAX_FILES = 512
EXACT = {"CLASSIFICATION.txt", "SHA256SUMS.txt",
         "etc/config/singbox", "etc/config/openclash"}
PREFIXES = ("etc/sing-box/", "etc/openclash/config/", "etc/openclash/custom/",
            "etc/openclash/proxy_provider/", "etc/openclash/rule_provider/",
            "etc/openclash/backup/")
SUM = re.compile(r"([0-9a-f]{64})\s+\*?(.+)")


def _allowed(name: str) -> bool:
    return name in EXACT or any(name.startswith(prefix) for prefix in PREFIXES)


def read_verified_archive(path: Path) -> dict[str, bytes]:
    if path.stat().st_size > MAX_ARCHIVE:
        raise ValueError("archive too large")
    files = {}
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        if len(members) > MAX_FILES:
            raise ValueError("too many archive members")
        for member in members:
            name = member.name.removeprefix("./")
            parts = PurePosixPath(name).parts
            if (not name or name.startswith("/") or ".." in parts
                    or member.issym() or member.islnk()):
                raise ValueError("unsafe archive member")
            if member.isdir():
                continue
            if not member.isfile() or not _allowed(name) or name in files:
                raise ValueError("unexpected archive member")
            if member.size > MAX_MEMBER:
                raise ValueError("archive member too large")
            files[name] = archive.extractfile(member).read(MAX_MEMBER + 1)
    if not EXACT.issubset(files):
        raise ValueError("required proxy migration member missing")
    sums = {}
    for line in files["SHA256SUMS.txt"].decode("ascii").splitlines():
        match = SUM.fullmatch(line)
        name = match.group(2).removeprefix("./") if match else ""
        if not match or name in sums:
            raise ValueError("invalid checksum manifest")
        sums[name] = match.group(1)
    data_names = set(files) - {"SHA256SUMS.txt"}
    if set(sums) != data_names:
        raise ValueError("checksum manifest coverage mismatch")
    if any(hashlib.sha256(files[name]).hexdigest() != sums[name]
           for name in data_names):
        raise ValueError("proxy migration checksum mismatch")
    if any(payload.startswith(b"\x7fELF") for name, payload in files.items()
           if name != "SHA256SUMS.txt"):
        raise ValueError("legacy executable included in configuration archive")
    return files


def inspect(path: Path) -> dict:
    files = read_verified_archive(path)
    names = set(files)
    groups = {
        "singbox_uci": int("etc/config/singbox" in names),
        "openclash_uci": int("etc/config/openclash" in names),
        "singbox_data_files": sum(name.startswith("etc/sing-box/") for name in names),
        "openclash_configs": sum(name.startswith("etc/openclash/config/") for name in names),
        "openclash_custom_files": sum(name.startswith("etc/openclash/custom/") for name in names),
        "openclash_provider_files": sum(name.startswith((
            "etc/openclash/proxy_provider/", "etc/openclash/rule_provider/"))
            for name in names),
        "openclash_backup_files": sum(name.startswith("etc/openclash/backup/")
                                      for name in names),
    }
    blockers = ["SINGBOX_SCHEMA_CONVERTER_NOT_RUNTIME_TESTED",
                "OPENCLASH_CROSS_VERSION_RESTORE_NOT_RUNTIME_TESTED",
                "PROXY_BACKEND_SELECTION_REQUIRES_EXPLICIT_CHOICE"]
    if groups["singbox_data_files"] == 0:
        blockers.append("SINGBOX_DATA_FILES_MISSING")
    return {
        "classification": "PRIVATE_PROXY_INVENTORY_NOT_RESTORE_OR_FLASH_APPROVAL",
        "decision": "BLOCKED_FIRST_MIGRATION",
        "verified_file_count": len(files) - 2,
        "inventory": groups,
        "legacy_executable_files_included": False,
        "secret_values_emitted": False,
        "blockers": blockers,
        "next_step": "Convert into an isolated V4 candidate and validate both backends before restore.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = inspect(args.archive)
    except (OSError, UnicodeError, ValueError, tarfile.TarError):
        report = {"classification": "PRIVATE_PROXY_INVENTORY_NOT_RESTORE_OR_FLASH_APPROVAL",
                  "decision": "BLOCKED_INVALID_INPUT",
                  "blockers": ["INPUT_UNREADABLE_OR_INVALID"],
                  "secret_values_emitted": False}
    body = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(body, encoding="utf-8")
    print(body, end="")
    return 2


if __name__ == "__main__":
    sys.exit(main())
