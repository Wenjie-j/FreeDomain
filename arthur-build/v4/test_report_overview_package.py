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

    def extracted_fixture(self):
        extracted = self.base / "extracted"
        shutil.copytree(self.root, extracted)
        metadata = extracted / audit.APK_FILE_LIST
        metadata.parent.mkdir(parents=True)
        metadata.write_text("".join(f"/{name}\n" for name in sorted(audit.FILES)))
        metadata.chmod(0o644)
        return extracted

    def test_independently_extracted_payload_must_match_staged_files(self):
        extracted = self.extracted_fixture()
        report, _ = audit.build_report(self.root, self.apk, self.config,
                                       self.source, self.owners, extracted)
        self.assertTrue(report["apk_payload_independently_extracted"])
        self.assertEqual(set(report["apk_bookkeeping_sha256"]), {audit.APK_FILE_LIST})
        view = extracted / next(iter(audit.FILES))
        view.write_bytes(view.read_bytes() + b"\n// unexpected APK bytes\n")
        with self.assertRaisesRegex(ValueError, "extracted APK differs"):
            audit.build_report(self.root, self.apk, self.config,
                               self.source, self.owners, extracted)
        view.write_bytes((self.root / next(iter(audit.FILES))).read_bytes())
        injected = extracted / "etc/init.d/extra"
        injected.parent.mkdir(parents=True)
        injected.write_text("unexpected")
        with self.assertRaisesRegex(ValueError, "unexpected files"):
            audit.build_report(self.root, self.apk, self.config,
                               self.source, self.owners, extracted)

    def test_extracted_bookkeeping_is_required_and_cannot_list_extra_files(self):
        extracted = self.extracted_fixture()
        metadata = extracted / audit.APK_FILE_LIST
        original = metadata.read_bytes()
        for data in (b"", original + b"/etc/init.d/extra\n",
                     original.replace(b"/www/", b"/changed/")):
            metadata.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "file list differs"):
                audit.build_report(self.root, self.apk, self.config,
                                   self.source, self.owners, extracted)
        metadata.unlink()
        with self.assertRaisesRegex(ValueError, "unexpected files"):
            audit.build_report(self.root, self.apk, self.config,
                               self.source, self.owners, extracted)

    def test_other_bookkeeping_files_are_not_ignored(self):
        extracted = self.extracted_fixture()
        (extracted / "lib/apk/packages/foreign.list").write_text("/etc/init.d/extra\n")
        with self.assertRaisesRegex(ValueError, "unexpected files"):
            audit.build_report(self.root, self.apk, self.config,
                               self.source, self.owners, extracted)

    def test_extracted_symlinks_executable_data_and_special_files_block(self):
        import os
        extracted = self.extracted_fixture()
        metadata = extracted / audit.APK_FILE_LIST
        original = metadata.read_bytes()
        metadata.unlink()
        metadata.symlink_to(self.config)
        with self.assertRaisesRegex(ValueError, "unexpected files"):
            audit.build_report(self.root, self.apk, self.config,
                               self.source, self.owners, extracted)
        metadata.unlink()
        metadata.write_bytes(original)
        for name in (audit.APK_FILE_LIST, next(iter(audit.FILES))):
            target = extracted / name
            target.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "executable"):
                audit.build_report(self.root, self.apk, self.config,
                                   self.source, self.owners, extracted)
            target.chmod(0o644)
        os.mkfifo(extracted / "unexpected-fifo")
        with self.assertRaisesRegex(ValueError, "unexpected files"):
            audit.build_report(self.root, self.apk, self.config,
                               self.source, self.owners, extracted)

    def test_image_selection_missing_archive_and_symlink_archive_block(self):
        self.config.write_text("CONFIG_PACKAGE_luci-app-arthur-overview=y\n")
        with self.assertRaisesRegex(ValueError, "outside the image"):
            self.check()
        diagnostic, _ = audit.build_report(self.root, self.apk, self.config,
                                           self.source, self.owners,
                                           allow_diagnostic_root_probe=True)
        self.assertTrue(diagnostic["diagnostic_root_probe_selected"])
        self.assertFalse(diagnostic["firmware_inclusion_approved"])
        self.assertFalse(diagnostic["luci_runtime_verified"])
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
