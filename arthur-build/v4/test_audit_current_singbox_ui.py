import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("audit_current_ui", HERE / "audit_current_singbox_ui.py")
auditor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auditor)


def make_archive(path, members):
    with tarfile.open(path, "w:gz") as archive:
        for name, data in members:
            raw = data.encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))


class AuditSourceOnlyExport(unittest.TestCase):
    def test_reports_blockers_without_disclosing_archive_text(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.tar.gz"
            secret = "PRIVATE-SUBSCRIPTION-TOKEN-123"
            make_archive(path, [
                (auditor.SOURCE[0], 'entry({"admin","services","singbox","api","active"}, call("api_active"))'),
                (auditor.SOURCE[1], secret),
                ("usr/bin/sing-box-firewall", 'HY2_IP="123.45.67.89"\niptables -A X'),
            ])
            report = auditor.audit(path)
            self.assertFalse(report["port_ready"])
            self.assertIn("service_setup_source_present", report["blockers"])
            self.assertIn("controller_enforces_post_method", report["blockers"])
            self.assertIn("no_legacy_firewall_commands", report["blockers"])
            rendered = json.dumps(report)
            self.assertNotIn(secret, rendered)
            self.assertNotIn("123.45.67.89", rendered)
            self.assertEqual(len(report["archive_sha256"]), 64)

    def test_old_cn_updater_does_not_supply_firewall_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mismatch.tar.gz"
            make_archive(path, [
                ("usr/bin/sing-box-firewall", 'CN_JSON="/etc/sing-box/rules/geoip-cn.json"'),
                ("usr/bin/sing-box-update-rules", "fetch geoip-cn.srs"),
            ])
            result = auditor.audit(path)
            self.assertFalse(result["checks"]["cn_firewall_list_updated"])
            self.assertIn("cn_firewall_list_updated", result["blockers"])

    def test_rejects_traversal_and_unexpected_member(self):
        for member in ("../private", "usr/lib/lua/../../private", "etc/config/singbox"):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "invalid.tar.gz"
                make_archive(path, [(member, "secret")])
                with self.assertRaises(ValueError):
                    auditor.audit(path)

    def test_rejects_duplicate_source_member(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.tar.gz"
            make_archive(path, [(auditor.SOURCE[0], "one"), (auditor.SOURCE[0], "two")])
            with self.assertRaises(ValueError):
                auditor.audit(path)

    def test_separate_service_export_resolves_setup_only(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.tar.gz"
            service = Path(directory) / "service.tar.gz"
            make_archive(source, [(auditor.SOURCE[0], "original controller")])
            make_archive(service, [("etc/init.d/sing-box-setup", "#!/bin/sh\n")])
            result = auditor.audit(source, service)
            self.assertTrue(result["checks"]["service_setup_source_present"])
            self.assertNotIn("etc/init.d/sing-box-setup", result["missing_expected_paths"])
            self.assertIn("no_legacy_firewall_commands", result["checks"])
            self.assertEqual(len(result["services_archive_sha256"]), 64)
            make_archive(service, [("etc/init.d/anyreality", "#!/bin/sh\n")])
            with self.assertRaises(ValueError):
                auditor.audit(source, service)


if __name__ == "__main__":
    unittest.main()
