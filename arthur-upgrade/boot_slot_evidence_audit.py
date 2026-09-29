#!/usr/bin/env python3
"""Audit private Arthur BOOTCONFIG/APPSBLENV captures without changing them."""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import tarfile
import zlib
from pathlib import Path


PARTITION_BYTES = 256 * 1024
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
SLOT_OFFSET = 148
CAPTURES = (
    "BOOTCONFIG-p2.img",
    "BOOTCONFIG1-p3.img",
    "APPSBLENV-p12.img",
)
MEMBERS = set(CAPTURES) | {"system.txt", "SHA256SUMS.txt"}
RECOGNIZED_ENV_NAMES = frozenset((
    "bootcmd", "bootargs", "bootdelay", "bootcount", "bootlimit",
    "boot_part", "boot_partition", "boot_slot", "active_slot",
    "active_partition", "upgrade_available", "tries_remaining",
    "bootmode", "boot_state",
))


def _nonzero_bounds(raw: bytes) -> tuple[int | None, int | None, int]:
    first = next((index for index, value in enumerate(raw) if value), None)
    if first is None:
        return None, None, 0
    last = len(raw) - 1 - next(index for index, value in enumerate(reversed(raw)) if value)
    return first, last, sum(value != 0 for value in raw)


def _summary(raw: bytes, label: str) -> dict:
    if len(raw) != PARTITION_BYTES:
        raise ValueError(f"{label} is not exactly 256 KiB")
    first, last, count = _nonzero_bounds(raw)
    return {
        "label": label,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "first_nonzero_offset": first,
        "last_nonzero_offset": last,
        "nonzero_bytes": count,
        "byte_148": raw[SLOT_OFFSET],
        "pinned_v4_target_pair": (
            "HLOS_1/rootfs_1" if raw[SLOT_OFFSET] == 1 else "HLOS/rootfs"
        ),
    }


def inspect_environment(raw: bytes) -> dict:
    if len(raw) != PARTITION_BYTES:
        raise ValueError("APPSBLENV capture is not exactly 256 KiB")
    stored_le = struct.unpack_from("<I", raw)[0]
    stored_be = struct.unpack_from(">I", raw)[0]
    calculated = zlib.crc32(raw[4:]) & 0xffffffff
    matches = []
    if calculated == stored_le:
        matches.append("little")
    if calculated == stored_be:
        matches.append("big")
    found = set()
    for field in raw[4:].split(b"\0"):
        if b"=" not in field:
            continue
        key = field.split(b"=", 1)[0]
        try:
            name = key.decode("ascii")
        except UnicodeDecodeError:
            continue
        if name in RECOGNIZED_ENV_NAMES:
            found.add(name)
    return {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "crc32_valid": bool(matches),
        "crc32_byte_order_matches": matches,
        "recognized_boot_variable_names": sorted(found),
        "note": "Environment values are intentionally omitted from this report.",
    }


def _checksums(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("SHA256SUMS.txt is not ASCII") from exc
    result = {}
    expected = set(CAPTURES) | {"system.txt"}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) != 2 or len(parts[0]) != 64 or parts[1] not in expected:
            raise ValueError("unexpected SHA256SUMS.txt entry")
        int(parts[0], 16)
        if parts[1] in result:
            raise ValueError("duplicate SHA256SUMS.txt entry")
        result[parts[1]] = parts[0].lower()
    if set(result) != expected:
        raise ValueError("SHA256SUMS.txt does not cover the expected evidence")
    return result


def inspect_archive(path: Path) -> dict:
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("boot-slot archive exceeds the inspection bound")
    with tarfile.open(path, mode="r:*") as source:
        by_name = {}
        for member in source.getmembers():
            if not member.isfile() or member.name in by_name:
                raise ValueError("boot-slot archive contains a non-file or duplicate")
            by_name[member.name] = member
        if set(by_name) != MEMBERS:
            raise ValueError("boot-slot archive member set is not recognized")
        for name in CAPTURES:
            if by_name[name].size != PARTITION_BYTES:
                raise ValueError(f"{name} is not exactly 256 KiB")
        if by_name["system.txt"].size > 64 * 1024 or by_name["SHA256SUMS.txt"].size > 4096:
            raise ValueError("boot-slot text member exceeds the inspection bound")
        raw = {}
        for name in MEMBERS:
            stream = source.extractfile(by_name[name])
            if stream is None:
                raise ValueError(f"cannot read {name}")
            raw[name] = stream.read(by_name[name].size + 1)

    manifest = _checksums(raw["SHA256SUMS.txt"])
    for name, digest in manifest.items():
        if hashlib.sha256(raw[name]).hexdigest() != digest:
            raise ValueError(f"stored checksum mismatch for {name}")

    primary = _summary(raw["BOOTCONFIG-p2.img"], "BOOTCONFIG/p2")
    backup = _summary(raw["BOOTCONFIG1-p3.img"], "BOOTCONFIG1/p3")
    environment = inspect_environment(raw["APPSBLENV-p12.img"])
    blockers = []
    if raw["BOOTCONFIG-p2.img"] != raw["BOOTCONFIG1-p3.img"]:
        blockers.append("BOOTCONFIG_COPIES_DIFFER")
    if primary["byte_148"] not in (0, 1):
        blockers.append("BOOTCONFIG_BYTE_148_UNEXPECTED")
    if not environment["crc32_valid"]:
        blockers.append("APPSBLENV_CRC_INVALID")
    blockers.extend((
        "NO_ROOTFS_1_FOR_AB_ROLLBACK",
        "PINNED_V4_WRITE_TARGET_IS_SELECTED_SLOT_PAIR",
        "BOOTCONFIG_BYTE_148_MEANING_NOT_BOOT_TESTED_ON_ARTHUR",
        "BOOT_SLOT_SWITCH_AND_RECOVERY_NOT_PROVEN",
    ))
    return {
        "classification": "READ_ONLY_BOOT_SLOT_EVIDENCE_NOT_FLASH_APPROVAL",
        "archive": path.name,
        "checksums_match": True,
        "bootconfig_copies_identical": raw["BOOTCONFIG-p2.img"] == raw["BOOTCONFIG1-p3.img"],
        "bootconfig": {"primary": primary, "backup": backup},
        "appsblenv": environment,
        "write_approved": False,
        "decision": "BLOCKED_WRITE",
        "blockers": blockers,
        "warning": "Offset 148 follows the pinned V4 script; it is a hint, not an Arthur boot test.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = inspect_archive(args.archive)
    except (OSError, ValueError, tarfile.TarError, struct.error) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 3
    body = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(body)
    print(body)
    return 2


if __name__ == "__main__":
    sys.exit(main())
