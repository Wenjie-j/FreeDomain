import hashlib
import io
import json
import struct
import tarfile
import tempfile
import unittest
import zlib
from pathlib import Path

from boot_slot_evidence_audit import PARTITION_BYTES, inspect_archive


def environment(valid_crc=True):
    data = bytearray(b"\0" * (PARTITION_BYTES - 4))
    payload = b"bootcmd=bootipq\0password=DO_NOT_COPY\0\0"
    data[:len(payload)] = payload
    crc = zlib.crc32(data) & 0xffffffff
    if not valid_crc:
        crc ^= 1
    return struct.pack("<I", crc) + data


def make_archive(path, primary_slot=0, backup_slot=0, valid_env_crc=True,
                 corrupt_manifest=False):
    primary = bytearray(PARTITION_BYTES)
    backup = bytearray(PARTITION_BYTES)
    primary[148] = primary_slot
    backup[148] = backup_slot
    files = {
        "BOOTCONFIG-p2.img": bytes(primary),
        "BOOTCONFIG1-p3.img": bytes(backup),
        "APPSBLENV-p12.img": environment(valid_env_crc),
        "system.txt": b"classification=READ_ONLY_PRIVATE_BOOT_SLOT_EVIDENCE\n",
    }
    checksums = []
    for name, raw in files.items():
        digest = hashlib.sha256(raw).hexdigest()
        if corrupt_manifest and name == "BOOTCONFIG1-p3.img":
            digest = "0" * 64
        checksums.append(f"{digest}  {name}\n")
    files["SHA256SUMS.txt"] = "".join(checksums).encode()
    with tarfile.open(path, "w:gz") as target:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            target.addfile(info, io.BytesIO(raw))


class BootSlotEvidenceAuditTests(unittest.TestCase):
    def inspect(self, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boot-slot.tar.gz"
            make_archive(path, **kwargs)
            return inspect_archive(path)

    def test_identical_slot_zero_copies_are_reported_but_never_approved(self):
        report = self.inspect()
        self.assertTrue(report["bootconfig_copies_identical"])
        self.assertEqual(report["bootconfig"]["primary"]["byte_148"], 0)
        self.assertEqual(report["bootconfig"]["primary"]["pinned_v4_target_pair"],
                         "HLOS/rootfs")
        self.assertTrue(report["appsblenv"]["crc32_valid"])
        self.assertFalse(report["write_approved"])
        self.assertIn("PINNED_V4_WRITE_TARGET_IS_SELECTED_SLOT_PAIR",
                      report["blockers"])
        self.assertNotIn("DO_NOT_COPY", json.dumps(report))

    def test_slot_one_maps_to_missing_rootfs_1_pair(self):
        report = self.inspect(primary_slot=1, backup_slot=1)
        self.assertEqual(report["bootconfig"]["primary"]["pinned_v4_target_pair"],
                         "HLOS_1/rootfs_1")
        self.assertIn("NO_ROOTFS_1_FOR_AB_ROLLBACK", report["blockers"])

    def test_different_bootconfig_copies_and_bad_env_crc_are_blocked(self):
        report = self.inspect(backup_slot=1, valid_env_crc=False)
        self.assertIn("BOOTCONFIG_COPIES_DIFFER", report["blockers"])
        self.assertIn("APPSBLENV_CRC_INVALID", report["blockers"])

    def test_unexpected_slot_byte_is_blocked(self):
        report = self.inspect(primary_slot=7, backup_slot=7)
        self.assertIn("BOOTCONFIG_BYTE_148_UNEXPECTED", report["blockers"])

    def test_manifest_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boot-slot.tar.gz"
            make_archive(path, corrupt_manifest=True)
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                inspect_archive(path)


if __name__ == "__main__":
    unittest.main()
