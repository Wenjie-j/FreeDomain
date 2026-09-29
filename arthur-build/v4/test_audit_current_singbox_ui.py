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


if __name__ == "__main__":
    unittest.main()
