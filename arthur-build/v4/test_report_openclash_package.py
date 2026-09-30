import importlib.util
import pathlib
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "openclash_report", HERE / "report_openclash_package.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OpenClashPackageReportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = pathlib.Path(self.temp.name)
        self.root = self.base / ".pkgdir/luci-app-openclash"
        for name in module.REQUIRED_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("payload\n")
        (self.root / "etc/uci-defaults/luci-openclash").write_text(
            "mkdir -p /lib/upgrade/keep.d\n"
            "cat > /lib/upgrade/keep.d/luci-app-openclash <<EOF\n"
            "/etc/openclash/\nEOF\n")
        self.apk = self.base / "luci-app-openclash-0.47.156-rbeta.apk"
        self.apk.write_bytes(b"ADB package")
        self.config = self.base / ".config"
        self.config.write_text("CONFIG_PACKAGE_luci-app-openclash=y\n")
        self.owners = {
            "usr/bin/sing-box": ["sing-box"],
            "usr/bin/sing-box-firewall4": ["arthur-singbox-firewall4-test"],
        }
        self.lock = {"openclash_source": {
            "repository": "https://github.com/vernesong/OpenClash.git",
            "revision": module.EXPECTED_SOURCE,
            "package_path": "luci-app-openclash",
        }}

    def tearDown(self):
        self.temp.cleanup()

    def test_reports_payload_and_extends_file_owners(self):
        report, owners = module.build_report(
            self.root, self.apk, self.config, self.owners, self.lock)
        self.assertEqual(report["status"], "PACKAGE_PAYLOAD_AUDITED")
        self.assertTrue(report["sysupgrade_config_preservation_declared"])
        self.assertEqual(owners["etc/config/openclash"], ["luci-app-openclash"])
        self.assertEqual(owners["usr/bin/sing-box"], ["sing-box"])

    def test_rejects_backend_collision_and_missing_preservation(self):
        collision = self.root / "usr/bin/sing-box"
        collision.parent.mkdir(parents=True, exist_ok=True)
        collision.write_text("collision")
        with self.assertRaisesRegex(ValueError, "collision"):
            module.build_report(self.root, self.apk, self.config, self.owners, self.lock)
        collision.unlink()
        (self.root / "etc/uci-defaults/luci-openclash").write_text("exit 0\n")
        with self.assertRaisesRegex(ValueError, "preservation"):
            module.build_report(self.root, self.apk, self.config, self.owners, self.lock)


if __name__ == "__main__":
    unittest.main()
