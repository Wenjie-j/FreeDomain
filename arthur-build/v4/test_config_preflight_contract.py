from pathlib import Path
import json
import unittest


WORKFLOW = (Path(__file__).parents[2] / ".github/workflows/arthur-v4-config-preflight.yml")


class ConfigPreflightContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text()

    def test_reports_payload_only_staging_trees(self):
        self.assertIn("-path '*/.pkgdir/sing-box'", self.source)
        self.assertIn(
            "-path '*/arthur-singbox-firewall4-test-0.1/"
            ".pkgdir/arthur-singbox-firewall4-test'",
            self.source,
        )
        self.assertNotIn("-path '*/ipkg-*/sing-box'", self.source)

    def test_built_packages_have_reports_and_uploaded_evidence(self):
        for name in (
            "report_core_package.py",
            "report_firewall4_test_package.py",
            "v4-core-build-trace.json",
            "v4-core-file-owners.json",
            "v4-firewall4-package-build.json",
            "v4-package-file-owners.partial.json",
        ):
            with self.subTest(name=name):
                self.assertIn(name, self.source)
        self.assertIn("--core-owners ../v4-core-file-owners.json", self.source)

    def test_openclash_is_a_required_resolved_package(self):
        self.assertIn("'PACKAGE_luci-app-openclash'", self.source)
        lock = json.loads((WORKFLOW.parents[2] / "arthur-build/v4/feeds.lock.json").read_text())
        self.assertEqual(lock["openclash_source"]["revision"],
                         "c3a33c1d3407956fdf8f0e0b7c1a4c52e6ad9593")
        self.assertIn("git -C \"$RUNNER_TEMP/OpenClash\" checkout \"$openclash_rev\"", self.source)
        self.assertIn("package/arthur/luci-app-openclash/compile", self.source)
        self.assertIn("v4-openclash-package.sha256", self.source)


if __name__ == "__main__":
    unittest.main()
