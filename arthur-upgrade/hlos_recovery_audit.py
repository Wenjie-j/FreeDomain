#!/usr/bin/env python3
"""Read-only audit of backed-up Arthur HLOS/HLOS_1 partitions.

This tool intentionally cannot approve or perform a flash.  It reports whether
the two 6 MiB partition captures contain a verifiable FIT at byte zero and
flags unexplained data in the nominal backup partition.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import tarfile
from pathlib import Path

from fit_integrity import inspect_fit_memory, verify_fit


PARTITION_BYTES = 6 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024
FIT_MAGIC = b"\xd0\x0d\xfe\xed"
SQUASHFS_MAGIC = b"hsqs"
EXPECTED_MEMBERS = ("p16-HLOS.img", "p17-HLOS_1.img")


def _marker_offsets(raw: bytes, marker: bytes, limit: int = 16) -> list[int]:
    offsets = []
    start = 0
    while len(offsets) < limit:
        found = raw.find(marker, start)
        if found < 0:
            break
        offsets.append(found)
        start = found + 1
    return offsets


def _nonzero_bounds(raw: bytes) -> tuple[int | None, int | None, int]:
    first = next((index for index, value in enumerate(raw) if value), None)
    if first is None:
        return None, None, 0
    last = len(raw) - 1 - next(index for index, value in enumerate(reversed(raw)) if value)
    return first, last, sum(value != 0 for value in raw)


def inspect_partition(raw: bytes, label: str) -> dict:
    if len(raw) != PARTITION_BYTES:
        raise ValueError(f"{label} capture is not exactly 6 MiB")

    first, last, nonzero = _nonzero_bounds(raw)
    result = {
        "label": label,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "first_nonzero_offset": first,
        "last_nonzero_offset": last,
        "nonzero_bytes": nonzero,
        "squashfs_marker_offsets": _marker_offsets(raw, SQUASHFS_MAGIC),
        "fit_at_offset_zero": False,
        "fit_verified": False,
    }

    if raw[:4] != FIT_MAGIC:
        result["fit_status"] = "NO_FIT_MAGIC_AT_OFFSET_ZERO"
        return result

    total = struct.unpack_from(">I", raw, 4)[0]
    result["fit_bytes"] = total
    result["fit_at_offset_zero"] = True
    if total < 40 or total > len(raw):
        result["fit_status"] = "INVALID_FIT_SIZE"
        return result

    fit = raw[:total]
    try:
        algorithms = verify_fit(fit)
        memory_profile = inspect_fit_memory(fit)
    except (KeyError, TypeError, ValueError, struct.error) as exc:
        result["fit_status"] = "FIT_VERIFICATION_FAILED"
        result["fit_error"] = str(exc)
        return result

    result.update({
        "fit_status": "VERIFIED_INLINE_SUBIMAGE_HASHES",
        "fit_verified": True,
        "fit_subimage_hash_algorithms": algorithms,
        "fit_memory_profile": memory_profile,
        "fit_headroom_bytes": len(raw) - total,
        "trailing_nonzero_bytes": sum(value != 0 for value in raw[total:]),
    })
    return result


def _read_checksums(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("SHA256SUMS.txt is not ASCII") from exc
    checksums = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        if len(parts) != 2 or len(parts[0]) != 64 or parts[1] not in EXPECTED_MEMBERS:
            raise ValueError("unexpected SHA256SUMS.txt entry")
        int(parts[0], 16)
        if parts[1] in checksums:
            raise ValueError("duplicate SHA256SUMS.txt entry")
        checksums[parts[1]] = parts[0].lower()
    if set(checksums) != set(EXPECTED_MEMBERS):
        raise ValueError("SHA256SUMS.txt does not cover both HLOS captures")
    return checksums


def inspect_archive(path: Path) -> dict:
    if path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("HLOS archive exceeds the read-only inspection bound")

    with tarfile.open(path, mode="r:*") as source:
        members = source.getmembers()
        by_name = {}
        for member in members:
            if not member.isfile():
                raise ValueError("HLOS archive may contain regular files only")
            if member.name in by_name:
                raise ValueError("duplicate HLOS archive member")
            by_name[member.name] = member
        allowed = set(EXPECTED_MEMBERS) | {"SHA256SUMS.txt"}
        if set(by_name) != allowed:
            raise ValueError("HLOS archive member set is not recognized")
        if any(by_name[name].size > MAX_MEMBER_BYTES for name in EXPECTED_MEMBERS):
            raise ValueError("HLOS member exceeds the inspection bound")

        captures = {}
        for name in EXPECTED_MEMBERS:
            stream = source.extractfile(by_name[name])
            if stream is None:
                raise ValueError(f"cannot read {name}")
            captures[name] = stream.read(MAX_MEMBER_BYTES + 1)
        checksum_stream = source.extractfile(by_name["SHA256SUMS.txt"])
        if checksum_stream is None or by_name["SHA256SUMS.txt"].size > 4096:
            raise ValueError("invalid SHA256SUMS.txt")
        checksums = _read_checksums(checksum_stream.read(4097))

    for name, raw in captures.items():
        if hashlib.sha256(raw).hexdigest() != checksums[name]:
            raise ValueError(f"stored checksum mismatch for {name}")

    hlos = inspect_partition(captures[EXPECTED_MEMBERS[0]], "HLOS/p16")
    backup = inspect_partition(captures[EXPECTED_MEMBERS[1]], "HLOS_1/p17")
    blockers = []
    if not hlos["fit_verified"]:
        blockers.append("HLOS_NO_VERIFIED_FIT_AT_OFFSET_ZERO")
    if not backup["fit_verified"]:
        blockers.append("HLOS_1_NO_VERIFIED_FIT_AT_OFFSET_ZERO")
    if backup["nonzero_bytes"] and not backup["fit_verified"]:
        blockers.append("HLOS_1_CONTAINS_UNCLASSIFIED_NONZERO_DATA")
    if backup["squashfs_marker_offsets"]:
        blockers.append("HLOS_1_SQUASHFS_MARKER_REQUIRES_CLASSIFICATION")
    blockers.extend((
        "BOOT_SLOT_SELECTION_MECHANISM_NOT_CAPTURED",
        "HLOS_1_BOOT_NOT_PROVEN",
    ))
    return {
        "classification": "READ_ONLY_RECOVERY_EVIDENCE_NOT_FLASH_APPROVAL",
        "archive": path.name,
        "checksums_match": True,
        "partitions": {"hlos": hlos, "hlos_1": backup},
        "write_approved": False,
        "decision": "BLOCKED_WRITE",
        "blockers": blockers,
        "warning": "Partition bytes were inspected offline; no router or boot state was changed.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = inspect_archive(args.archive)
    except (OSError, ValueError, tarfile.TarError) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 3
    body = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(body)
    print(body)
    return 2


if __name__ == "__main__":
    sys.exit(main())
