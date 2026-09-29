#!/usr/bin/env python3
"""Validate saved GPT head/tail captures without writing a block device."""
from __future__ import annotations

import argparse
import json
import struct
import sys
import zlib
from pathlib import Path


SECTOR_BYTES = 512
GPT_SIGNATURE = b"EFI PART"
MAX_CAPTURE_BYTES = 4 * 1024 * 1024
MAX_ENTRY_ARRAY_BYTES = 2 * 1024 * 1024


class Captures:
    def __init__(self, head: bytes, tail: bytes, disk_bytes: int):
        if (not head or not tail or len(head) > MAX_CAPTURE_BYTES
                or len(tail) > MAX_CAPTURE_BYTES):
            raise ValueError("GPT capture size is outside the inspection bound")
        if any(value % SECTOR_BYTES for value in (len(head), len(tail), disk_bytes)):
            raise ValueError("GPT captures and disk size must be sector aligned")
        if disk_bytes < len(head) + len(tail):
            raise ValueError("disk size is smaller than the captures")
        self.head = head
        self.tail = tail
        self.disk_lbas = disk_bytes // SECTOR_BYTES
        self.tail_lba = self.disk_lbas - len(tail) // SECTOR_BYTES

    def read(self, lba: int, size: int) -> bytes:
        if lba < 0 or size < 0 or size > MAX_ENTRY_ARRAY_BYTES:
            raise ValueError("GPT read is outside the inspection bound")
        offset = lba * SECTOR_BYTES
        if offset + size <= len(self.head):
            return self.head[offset:offset + size]
        tail_offset = offset - self.tail_lba * SECTOR_BYTES
        if 0 <= tail_offset and tail_offset + size <= len(self.tail):
            return self.tail[tail_offset:tail_offset + size]
        raise ValueError("requested GPT bytes are not present in head/tail captures")


def inspect_header(captures: Captures, lba: int) -> dict:
    sector = captures.read(lba, SECTOR_BYTES)
    if sector[:8] != GPT_SIGNATURE:
        return {
            "lba": lba,
            "present": False,
            "valid": False,
            "status": "GPT_SIGNATURE_MISSING",
        }

    revision, header_size, stored_crc, reserved = struct.unpack_from("<IIII", sector, 8)
    if header_size < 92 or header_size > SECTOR_BYTES:
        return {"lba": lba, "present": True, "valid": False,
                "status": "INVALID_HEADER_SIZE"}
    header = bytearray(sector[:header_size])
    header[16:20] = b"\0" * 4
    calculated_crc = zlib.crc32(header) & 0xffffffff
    current_lba, backup_lba, first_usable, last_usable = struct.unpack_from(
        "<QQQQ", sector, 24)
    entry_lba = struct.unpack_from("<Q", sector, 72)[0]
    entry_count, entry_size, stored_entries_crc = struct.unpack_from("<III", sector, 80)
    entry_bytes = entry_count * entry_size
    structural = (
        revision == 0x00010000
        and reserved == 0
        and current_lba == lba
        and backup_lba < captures.disk_lbas
        and first_usable <= last_usable < captures.disk_lbas
        and 1 <= entry_count <= 4096
        and entry_size >= 128
        and entry_size % 8 == 0
        and entry_bytes <= MAX_ENTRY_ARRAY_BYTES
    )
    try:
        entries = captures.read(entry_lba, entry_bytes)
        calculated_entries_crc = zlib.crc32(entries) & 0xffffffff
        entries_captured = True
    except ValueError:
        calculated_entries_crc = None
        entries_captured = False
    valid = (structural and calculated_crc == stored_crc and entries_captured
             and calculated_entries_crc == stored_entries_crc)
    return {
        "lba": lba,
        "present": True,
        "valid": valid,
        "status": "VALID_CAPTURED_GPT" if valid else "GPT_VALIDATION_FAILED",
        "header_crc_matches": calculated_crc == stored_crc,
        "current_lba": current_lba,
        "backup_lba": backup_lba,
        "first_usable_lba": first_usable,
        "last_usable_lba": last_usable,
        "partition_entry_lba": entry_lba,
        "partition_entry_count": entry_count,
        "partition_entry_size": entry_size,
        "partition_entries_captured": entries_captured,
        "partition_entries_crc_matches": (
            calculated_entries_crc == stored_entries_crc
            if entries_captured else False
        ),
    }


def inspect_captures(head: bytes, tail: bytes, disk_bytes: int) -> dict:
    captures = Captures(head, tail, disk_bytes)
    primary = inspect_header(captures, 1)
    terminal = inspect_header(captures, captures.disk_lbas - 1)
    blockers = []
    if not primary["valid"]:
        blockers.append("PRIMARY_GPT_CAPTURE_INVALID")
    elif primary["backup_lba"] != captures.disk_lbas - 1:
        blockers.append("PRIMARY_GPT_BACKUP_LBA_NOT_AT_CURRENT_DISK_END")
    if not terminal["present"]:
        blockers.append("TERMINAL_BACKUP_GPT_HEADER_MISSING")
    elif not terminal["valid"]:
        blockers.append("TERMINAL_BACKUP_GPT_CAPTURE_INVALID")
    blockers.append("GPT_REPAIR_AND_RECOVERY_PATH_NOT_APPROVED")
    return {
        "classification": "READ_ONLY_GPT_EVIDENCE_NOT_REPAIR_APPROVAL",
        "disk_bytes": disk_bytes,
        "disk_lbas": captures.disk_lbas,
        "primary": primary,
        "terminal_backup": terminal,
        "write_approved": False,
        "decision": "BLOCKED_WRITE",
        "blockers": blockers,
        "warning": "Only saved captures were read; no disk or partition table was modified.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True, type=Path)
    parser.add_argument("--tail", required=True, type=Path)
    parser.add_argument("--disk-bytes", required=True, type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = inspect_captures(args.head.read_bytes(), args.tail.read_bytes(),
                                  args.disk_bytes)
    except (OSError, ValueError, struct.error) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 3
    body = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(body)
    print(body)
    return 2


if __name__ == "__main__":
    sys.exit(main())
