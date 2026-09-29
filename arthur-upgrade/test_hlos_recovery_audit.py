import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from hlos_recovery_audit import PARTITION_BYTES, inspect_archive, inspect_partition
from test_fit_integrity import dtb_fixture, fixture


def partition(payload=b""):
    if len(payload) > PARTITION_BYTES:
        raise ValueError("fixture is too large")
    return payload + b"\0" * (PARTITION_BYTES - len(payload))


def archive(path, hlos, backup, corrupt_checksum=False):
    checksums = {
        "p16-HLOS.img": hashlib.sha256(hlos).hexdigest(),
        "p17-HLOS_1.img": hashlib.sha256(backup).hexdigest(),
    }
    if corrupt_checksum:
        checksums["p17-HLOS_1.img"] = "0" * 64
    members = {
        "p16-HLOS.img": hlos,
        "p17-HLOS_1.img": backup,
        "SHA256SUMS.txt": "".join(
            f"{digest}  {name}\n" for name, digest in checksums.items()
        ).encode(),
    }
    with tarfile.open(path, "w:gz") as target:
        for name, raw in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            target.addfile(info, io.BytesIO(raw))


class HlosRecoveryAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fit = fixture(dtb_fixture(0x20000000))

    def test_verified_fit_at_zero_is_reported_without_boot_approval(self):
        report = inspect_partition(partition(self.fit), "HLOS/p16")
        self.assertTrue(report["fit_verified"])
        self.assertEqual(report["fit_memory_profile"], "STATIC_512M_BLOCKED")
        self.assertEqual(report["trailing_nonzero_bytes"], 0)

    def test_non_fit_backup_with_squashfs_marker_is_explicitly_blocked(self):
        backup = bytearray(PARTITION_BYTES)
        backup[-262144:-262140] = b"hsqs"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pair.tar.gz"
            archive(path, partition(self.fit), bytes(backup))
            report = inspect_archive(path)
        self.assertFalse(report["write_approved"])
        self.assertIn("HLOS_1_NO_VERIFIED_FIT_AT_OFFSET_ZERO", report["blockers"])
        self.assertIn("HLOS_1_CONTAINS_UNCLASSIFIED_NONZERO_DATA", report["blockers"])
        self.assertIn("HLOS_1_SQUASHFS_MARKER_REQUIRES_CLASSIFICATION", report["blockers"])
        self.assertEqual(report["partitions"]["hlos_1"]["squashfs_marker_offsets"],
                         [PARTITION_BYTES - 262144])

    def test_blank_backup_is_not_misrepresented_as_recovery_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pair.tar.gz"
            archive(path, partition(self.fit), partition())
            report = inspect_archive(path)
        self.assertIn("HLOS_1_NO_VERIFIED_FIT_AT_OFFSET_ZERO", report["blockers"])
        self.assertNotIn("HLOS_1_CONTAINS_UNCLASSIFIED_NONZERO_DATA", report["blockers"])
        self.assertIn("HLOS_1_BOOT_NOT_PROVEN", report["blockers"])

    def test_stored_checksum_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pair.tar.gz"
            archive(path, partition(self.fit), partition(), corrupt_checksum=True)
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                inspect_archive(path)

    def test_wrong_partition_size_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly 6 MiB"):
            inspect_partition(b"short", "HLOS/p16")


if __name__ == "__main__":
    unittest.main()
