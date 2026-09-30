import json
import pathlib
import shutil
import tempfile
import unittest

import report_overview_package as audit


HERE = pathlib.Path(__file__).parent


class OverviewPayloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.source = self.base / "source"
        shutil.copytree(HERE / "luci-app-arthur-overview", self.source)
        self.root = self.base / "payload"
        for installed, original in audit.FILES.items():
            target = self.root / installed
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.source / original, target)
            target.chmod(0o644)
        self.apk = self.base / "luci-app-arthur-overview-0.1-r1.apk"
        # Synthetic archive fixture: this test is not an APK parser or build.
        self.apk.write_bytes(b"synthetic paired APK")
        self.config = self.base / "config"
        self.config.write_text("CONFIG_PACKAGE_luci-app-arthur-overview=m\n")
        self.owners = {"usr/bin/sing-box": ["sing-box"]}

    def check(self):
        return audit.build_report(self.root, self.apk, self.config, self.source, self.owners)

    def test_valid_payload_preserves_existing_ownership_and_limits_claims(self):
        report, owners = self.check()
        self.assertEqual(report["status"], "READ_ONLY_STAGED_PAYLOAD_VERIFIED")
        self.assertFalse(report["apk_payload_independently_extracted"])
        self.assertFalse(report["luci_runtime_verified"])
        self.assertFalse(report["firmware_inclusion_approved"])
        self.assertEqual(owners["usr/bin/sing-box"], ["sing-box"])
        self.assertEqual(len(report["staged_file_sha256"]), 3)

    def test_modified_view_or_extra_init_script_blocks(self):
        view = self.root / next(iter(audit.FILES))
        original = view.read_bytes()
        view.write_bytes(original + b"\n// changed\n")
        with self.assertRaisesRegex(ValueError, "differs"):
            self.check()
        view.write_bytes(original)
        init = self.root / "etc/init.d/arthur-overview"
        init.parent.mkdir(parents=True)
        init.write_text("#!/bin/sh\n")
        with self.assertRaisesRegex(ValueError, "unexpected"):
            self.check()

    def test_excessive_acl_blocks_even_if_source_and_payload_match(self):
        name = "usr/share/rpcd/acl.d/luci-app-arthur-overview.json"
        acl = json.loads((self.root / name).read_text())
        acl[audit.PACKAGE]["write"] = {"ubus": {"system": ["reboot"]}}
        for file in (self.root / name, self.source / audit.FILES[name]):
            file.write_text(json.dumps(acl))
        with self.assertRaisesRegex(ValueError, "read-only contract"):
            self.check()

    def test_menu_cannot_change_to_another_action(self):
        name = "usr/share/luci/menu.d/luci-app-arthur-overview.json"
        menu = json.loads((self.root / name).read_text())
        menu["admin/status/arthur"]["action"] = {"type": "call", "function": "apply"}
        for file in (self.root / name, self.source / audit.FILES[name]):
            file.write_text(json.dumps(menu))
        with self.assertRaisesRegex(ValueError, "menu"):
            self.check()

    def test_symlink_payload_and_executable_data_block(self):
        name = next(iter(audit.FILES))
        target = self.root / name
        target.unlink()
        target.symlink_to(self.source / audit.FILES[name])
        with self.assertRaisesRegex(ValueError, "unexpected"):
            self.check()
        target.unlink()
        shutil.copyfile(self.source / audit.FILES[name], target)
        target.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "executable"):
            self.check()

    def test_colliding_owner_cannot_be_overwritten(self):
        self.owners[next(iter(audit.FILES))] = ["another-ui"]
        with self.assertRaisesRegex(ValueError, "collision"):
            self.check()

    def test_image_selection_missing_archive_and_symlink_archive_block(self):
        self.config.write_text("CONFIG_PACKAGE_luci-app-arthur-overview=y\n")
        with self.assertRaisesRegex(ValueError, "outside the image"):
            self.check()
        self.config.write_text("CONFIG_PACKAGE_luci-app-arthur-overview=m\n")
        self.apk.unlink()
        with self.assertRaisesRegex(ValueError, "APK missing"):
            self.check()
        other = self.base / "other.apk"
        other.write_bytes(b"synthetic APK")
        self.apk.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "APK missing"):
            self.check()


if __name__ == "__main__":
    unittest.main()
