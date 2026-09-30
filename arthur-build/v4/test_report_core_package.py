import importlib.util
import pathlib
import tempfile
import unittest
from test_core_elf import synthetic_arm64_elf


path = pathlib.Path(__file__).with_name("report_core_package.py")
spec = importlib.util.spec_from_file_location("core_report", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CorePackageReportTest(unittest.TestCase):
    def test_reports_only_verified_core_file_and_rejects_default_service(self):
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            root = base / "ipkg-aarch64_cortex-a53/sing-box"
            binary = root / "usr/bin/sing-box"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(synthetic_arm64_elf())
            binary.chmod(0o755)
            apk = base / "bin/packages/aarch64_cortex-a53/packages/sing-box-1.14.1-r1.apk"
            apk.parent.mkdir(parents=True)
            apk.write_bytes(b"ADBsample")
            config = base / ".config"
            config.write_text("\n".join([
                'CONFIG_TARGET_ARCH_PACKAGES="aarch64_cortex-a53"',
                "CONFIG_PACKAGE_sing-box=y",
                *(flag + "=y" for flag in module.TAG_FLAGS.values()),
            ]))
            trace, owners, report = module.build_reports(root, apk, config)
            self.assertEqual(trace["source_version"], "1.14.1")
            self.assertEqual(owners, {"usr/bin/sing-box": ["sing-box"]})
            self.assertEqual(report["staged_package_files"], ["usr/bin/sing-box"])
            service = root / "etc/init.d/sing-box"
            service.parent.mkdir(parents=True)
            service.write_text("legacy init")
            with self.assertRaisesRegex(ValueError, "only usr/bin/sing-box"):
                module.build_reports(root, apk, config)
            service.unlink()
            config.write_text(config.read_text().replace("CONFIG_SINGBOX_WITH_QUIC=y", ""))
            with self.assertRaisesRegex(ValueError, "feature missing"):
                module.build_reports(root, apk, config)


if __name__ == "__main__":
    unittest.main()
