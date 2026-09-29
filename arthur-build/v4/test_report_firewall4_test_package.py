import importlib.util
import pathlib
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "firewall_report", HERE / "report_firewall4_test_package.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Firewall4PackageReportTest(unittest.TestCase):
    def test_reports_exact_non_activating_package(self):
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            root = base / "ipkg-all/arthur-singbox-firewall4-test"
            binary = root / module.EXPECTED_FILES[0]
            note = root / module.EXPECTED_FILES[1]
            binary.parent.mkdir(parents=True)
            note.parent.mkdir(parents=True)
            candidate = base / "candidate"
            candidate.write_text("#!/bin/sh\nnft list ruleset\n")
            binary.write_bytes(candidate.read_bytes())
            binary.chmod(0o755)
            note.write_text("test only\n")
            apk = base / "arthur-singbox-firewall4-test-0.1-r1.apk"
            apk.write_bytes(b"ADB package")
            config = base / ".config"
            config.write_text("CONFIG_PACKAGE_arthur-singbox-firewall4-test=m\n")
            report, owners = module.build_report(
                root, apk, config, candidate, {"usr/bin/sing-box": ["sing-box"]})
            self.assertEqual(report["status"], "TEST_PACKAGE_BUILT")
            self.assertFalse(report["automatic_activation_packaged"])
            self.assertEqual(owners["usr/bin/sing-box-firewall4"],
                             ["arthur-singbox-firewall4-test"])
            binary.write_text("#!/bin/sh\niptables -L\n")
            with self.assertRaises(ValueError):
                module.build_report(root, apk, config, candidate,
                                    {"usr/bin/sing-box": ["sing-box"]})


if __name__ == "__main__":
    unittest.main()
