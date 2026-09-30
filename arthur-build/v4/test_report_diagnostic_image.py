import hashlib
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import report_diagnostic_image as audit


class DiagnosticImageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.target = self.base / "target"
        self.target.mkdir()
        self.root = self.base / "root"
        self.root.mkdir()
        self.image = self.target / "openwrt-jdcloud_re-ss-01-squashfs-sysupgrade.bin"
        self.image.write_bytes(b"synthetic image; FIT inspection mocked")
        self.manifest = self.target / "openwrt-jdcloud_re-ss-01.manifest"
        self.manifest.write_text("sing-box - 1.14.1\n")
        self.config = self.base / "final.config"
        self.config.write_text("CONFIG_ATH11K_MEM_PROFILE_1G=y\n")
        self.inventory = json.loads((Path(__file__).parents[2] / "arthur-upgrade" /
                                    "inventory-arthur-1gb-v3.json").read_text())
        self.image_info = {
            "kernel_bytes": 5674292, "fits_hlos_6mib": True,
            "rootfs_bytes": 14880768,
            "fit_memory_profile": "STATIC_1G_DECLARED_RUNTIME_UNVERIFIED",
        }

    def report(self):
        with patch.object(audit, "inspect_image", return_value=self.image_info) as fit:
            result = audit.build_report(self.target, self.config, self.root,
                                        {}, {}, {}, self.inventory)
            fit.assert_called_once_with(self.image)
        return result

    def test_generated_image_inventory_uses_actual_manifest_and_stays_blocked(self):
        report = self.report()
        self.assertEqual(report["image_sha256"],
                         hashlib.sha256(self.image.read_bytes()).hexdigest())
        self.assertFalse(report["write_approved"])
        self.assertFalse(report["firmware_bytes_uploaded"])
        self.assertEqual(report["upgrade_gate"]["result"], "BLOCKED")
        self.assertIn("NO_SECOND_ROOTFS", report["upgrade_gate"]["blockers"])
        components = report["assembled_components"]
        self.assertEqual(components["component_gate"], "BLOCKED_INCOMPLETE_COMPONENTS")
        self.assertIn("luci-app-arthur-overview", components["missing_packages"]["familiar_ui"])
        self.assertNotIn("sing-box", components["missing_packages"]["proxy"])
        self.assertFalse(components["staged_root_files"]["usr/bin/sing-box"])

    def test_claiming_all_inventory_flags_does_not_approve_flash(self):
        for field, value in self.inventory.items():
            if isinstance(value, bool):
                self.inventory[field] = True
        report = self.report()
        self.assertFalse(report["upgrade_gate"]["write_approved"])
        self.assertIn("SIGNED_RELEASE_AND_PROVEN_ROLLBACK_NOT_YET_APPROVED",
                      report["upgrade_gate"]["blockers"])

    def test_ambiguous_or_symlinked_images_are_rejected(self):
        second = self.target / "second-jdcloud_re-ss-01-sysupgrade.bin"
        second.write_bytes(b"other image")
        with self.assertRaisesRegex(ValueError, "expected one"):
            self.report()
        second.unlink()
        self.image.unlink()
        self.image.symlink_to(self.config)
        with self.assertRaisesRegex(ValueError, "expected one"):
            self.report()

    def test_invalid_fit_cannot_produce_inspected_status(self):
        with patch.object(audit, "inspect_image", side_effect=ValueError("invalid FIT")):
            with self.assertRaisesRegex(ValueError, "invalid FIT"):
                audit.build_report(self.target, self.config, self.root,
                                   {}, {}, {}, self.inventory)

    def test_failed_inspection_writes_failure_metadata_and_nonzero_exit(self):
        metadata = self.base / "metadata.json"
        metadata.write_text("{}")
        output = self.base / "report.json"
        argv = []
        for name, path in (("target-dir", self.target), ("config", self.config),
                           ("root-dir", self.root), ("core-trace", metadata),
                           ("owners", metadata), ("openclash-trace", metadata),
                           ("inventory", metadata), ("output", output)):
            argv += ["--" + name, str(path)]
        with contextlib.redirect_stdout(io.StringIO()):
            result = audit.main(argv)
        self.assertEqual(result, 2)
        report = json.loads(output.read_text())
        self.assertEqual(report["status"], "BLOCKED_INVALID_DIAGNOSTIC_IMAGE")
        self.assertFalse(report["write_approved"])


if __name__ == "__main__":
    unittest.main()
