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
        self.assertIn("report_openclash_package.py", self.source)
        self.assertIn("v4-openclash-package-build.json", self.source)
        self.assertIn("--owners ../v4-package-file-owners.partial.json", self.source)

    def test_openclash_prepares_luci_host_translation_tool(self):
        self.assertIn("package/feeds/luci/luci-base/host/compile", self.source)
        self.assertIn("test -x staging_dir/hostpkg/bin/po2lmo", self.source)
        self.assertNotIn("test -x staging_dir/host/bin/po2lmo", self.source)
        self.assertLess(self.source.index("package/feeds/luci/luci-base/host/compile"),
                        self.source.index("make -j2 tools/install"))
        self.assertIn("po2lmo package/arthur/luci-app-openclash/po/zh-cn/openclash.zh-cn.po", self.source)
        self.assertIn("bash curl ruby ruby-yaml unzip wget", self.source)

    def test_mwan3_uses_nft_compatibility_provider_not_legacy_xtables(self):
        self.assertIn("'PACKAGE_iptables-nft'", self.source)
        self.assertIn("'PACKAGE_ip6tables-nft'", self.source)
        self.assertIn("'PACKAGE_iptables-zz-legacy'", self.source)
        self.assertIn("selected_forbidden_legacy_firewall_packages", self.source)

    def test_core_bytes_are_verified_before_module_packaging_not_published(self):
        for token in ("prepare_openclash_core.py", "report_openclash_core_package.py",
                      "package/arthur/arthur-openclash-core/compile",
                      "'PACKAGE_arthur-openclash-core'",
                      "v4-openclash-core-build-trace.json",
                      "v4-openclash-core-package-build.json"):
            self.assertIn(token, self.source)
        self.assertNotIn("openwrt/bin/packages/**/arthur-openclash-core-*.apk", self.source)

    def test_short_core_workflow_emulates_only_version_and_synthetic_config(self):
        short = WORKFLOW.with_name("arthur-v4-openclash-core-audit.yml").read_text()
        self.assertIn("smoke_openclash_core.py", short)
        self.assertIn("v4-openclash-core-qemu-smoke.json", short)
        upload = short.partition("- name: Upload metadata only")[2]
        self.assertTrue(upload)
        self.assertNotIn("clash_meta", upload)
        self.assertNotIn(".apk", upload)
        self.assertNotIn(".gz", upload)
        self.assertNotIn("**", upload)

    def test_overview_has_a_separate_build_and_payload_evidence_path(self):
        for token in ("package/arthur/luci-app-arthur-overview/compile",
                      "'PACKAGE_luci-app-arthur-overview'",
                      "report_overview_package.py", "v4-overview-package-build.json",
                      "*/luci-app-arthur-overview/.pkgdir/luci-app-arthur-overview"):
            self.assertIn(token, self.source)
        base = WORKFLOW.parents[2] / "arthur-build/v4"
        self.assertIn("CONFIG_PACKAGE_luci-app-arthur-overview=m",
                      (base / "candidate.config.fragment").read_text().splitlines())
        recipe = (base / "luci-app-arthur-overview/Makefile").read_text()
        self.assertIn("include $(TOPDIR)/feeds/luci/luci.mk", recipe)
        self.assertNotIn("include ../../luci.mk", recipe)


if __name__ == "__main__":
    unittest.main()
