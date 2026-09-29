"""Fail-closed offline unit tests; no real eMMC or firmware writes."""
import io
import json
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from ota_release_gate import inspect, main

ROOT = Path(__file__).resolve().parent
BASE = json.loads((ROOT / "baseline.json").read_text(encoding="utf-8"))

def sample_fit(board=b"jdcloud,re-ss-01", pad=0):
    body = b"config@cp03-c2|" + board + b"|JDC-RE-SS-01|" + b"\0" * (1024 + pad)
    return b"\xd0\x0d\xfe\xed" + struct.pack(">I", len(body) + 8) + body

def zip_fixture(path, fit, root=b"hsqs"):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tf:
        for part, data in (("kernel", fit), ("root", root)):
            item = tarfile.TarInfo("sysupgrade-jdcloud_re-ss-01/" + part)
            item.size = len(data)
            tf.addfile(item, io.BytesIO(data))
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("openwrt-qualcommax-ipq60xx-jdcloud_re-ss-01-squashfs-sysupgrade.bin", out.getvalue())

class TestFailClosed(unittest.TestCase):
    def test_matches_static_markers_but_blocks_flash(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d)/"test.zip"
            zip_fixture(f, sample_fit())
            r = inspect(f, BASE)
            self.assertTrue(r["static_checks"]["kernel_fits_hlos"])
            self.assertFalse(r["static_checks"]["fit_subimage_hashes_valid"])
            self.assertEqual(r["static_checks"]["fit_memory_profile"],
                             "INVALID_OR_UNVERIFIED_FIT")
            self.assertIn("UNVERIFIED_1G_FIT_MEMORY_MAP", r["hard_blockers"])
            self.assertEqual(r["decision"], "NO_GO_FOR_PRODUCTION_ROUTER")
            self.assertIn("UNVERIFIED_ROOTFS_1_PRESENT", r["hard_blockers"])
    def test_wrong_board_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d)/"test.zip"
            zip_fixture(f, sample_fit(board=b"some-other-board"))
            self.assertIn("STATIC_ARTIFACT_LAYOUT_OR_IDENTITY_CHECK_FAILED", inspect(f, BASE)["hard_blockers"])
    def test_oversize_kernel_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d)/"test.zip"
            zip_fixture(f, sample_fit(pad=6291457))
            self.assertFalse(inspect(f, BASE)["static_checks"]["kernel_fits_hlos"])
    def test_invalid_fit_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d)/"test.zip"
            zip_fixture(f, b"bad FIT" * 300)
            self.assertEqual(main(["--artifact",str(f),"--baseline",str(ROOT/"baseline.json")]), 2)
    def test_all_assertions_true_are_not_flash_approval(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d)/"test.zip"
            zip_fixture(f, sample_fit())
            b = dict(BASE, **{key: True for key in ("hlos_1_boot_verified","rootfs_1_present","backup_gpt_valid","independent_recovery_verified","bootloader_automatic_rollback_verified","first_migration_config_converter_verified","linux_612_runtime_1g_wifi_nss_verified")})
            self.assertEqual(inspect(f,b)["decision"], "NO_GO_FOR_PRODUCTION_ROUTER")

if __name__ == "__main__":
    unittest.main(verbosity=2)
