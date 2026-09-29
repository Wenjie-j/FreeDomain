import struct
import unittest
import zlib

from gpt_capture_audit import SECTOR_BYTES, inspect_captures


def header(current, backup, entries_lba, entries_crc, first, last):
    raw = bytearray(SECTOR_BYTES)
    raw[:8] = b"EFI PART"
    struct.pack_into("<IIII", raw, 8, 0x00010000, 92, 0, 0)
    struct.pack_into("<QQQQ", raw, 24, current, backup, first, last)
    raw[56:72] = bytes(range(16))
    struct.pack_into("<QIII", raw, 72, entries_lba, 128, 128, entries_crc)
    copy = bytearray(raw[:92])
    copy[16:20] = b"\0" * 4
    struct.pack_into("<I", raw, 16, zlib.crc32(copy) & 0xffffffff)
    return bytes(raw)


def captures(valid_terminal=True, stale_primary=False):
    disk_lbas = 16384
    capture_lbas = 2048
    head = bytearray(capture_lbas * SECTOR_BYTES)
    tail = bytearray(capture_lbas * SECTOR_BYTES)
    entries = bytes(128 * 128)
    entries_crc = zlib.crc32(entries) & 0xffffffff
    primary_backup = 8191 if stale_primary else disk_lbas - 1
    head[2 * SECTOR_BYTES:2 * SECTOR_BYTES + len(entries)] = entries
    head[SECTOR_BYTES:2 * SECTOR_BYTES] = header(
        1, primary_backup, 2, entries_crc, 34, disk_lbas - 34)
    if valid_terminal:
        tail_start_lba = disk_lbas - capture_lbas
        backup_entries_lba = disk_lbas - 33
        offset = (backup_entries_lba - tail_start_lba) * SECTOR_BYTES
        tail[offset:offset + len(entries)] = entries
        tail[-SECTOR_BYTES:] = header(
            disk_lbas - 1, 1, backup_entries_lba, entries_crc, 34, disk_lbas - 34)
    return bytes(head), bytes(tail), disk_lbas * SECTOR_BYTES


class GptCaptureAuditTests(unittest.TestCase):
    def test_matching_primary_and_terminal_backup_validate_but_never_approve_write(self):
        report = inspect_captures(*captures())
        self.assertTrue(report["primary"]["valid"])
        self.assertTrue(report["terminal_backup"]["valid"])
        self.assertFalse(report["write_approved"])
        self.assertEqual(report["blockers"], ["GPT_REPAIR_AND_RECOVERY_PATH_NOT_APPROVED"])

    def test_stale_primary_and_missing_terminal_backup_are_blocked(self):
        report = inspect_captures(*captures(valid_terminal=False, stale_primary=True))
        self.assertTrue(report["primary"]["valid"])
        self.assertFalse(report["terminal_backup"]["present"])
        self.assertIn("PRIMARY_GPT_BACKUP_LBA_NOT_AT_CURRENT_DISK_END",
                      report["blockers"])
        self.assertIn("TERMINAL_BACKUP_GPT_HEADER_MISSING", report["blockers"])

    def test_corrupt_primary_crc_fails_closed(self):
        head, tail, disk_bytes = captures()
        damaged = bytearray(head)
        damaged[SECTOR_BYTES + 24] ^= 1
        report = inspect_captures(bytes(damaged), tail, disk_bytes)
        self.assertFalse(report["primary"]["valid"])
        self.assertIn("PRIMARY_GPT_CAPTURE_INVALID", report["blockers"])


if __name__ == "__main__":
    unittest.main()
