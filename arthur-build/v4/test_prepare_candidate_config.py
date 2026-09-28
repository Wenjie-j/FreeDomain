import importlib.util
import pathlib
import unittest

base = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("candidate", base / "prepare_candidate_config.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ConfigCandidateTest(unittest.TestCase):
    def test_merges_without_repeated_or_conflicting_flags(self):
        original = """CONFIG_TARGET_qualcommax_ipq60xx_DEVICE_jdcloud_re-ss-01=y
CONFIG_PACKAGE_kmod-qca-nss-drv=y
CONFIG_PACKAGE_kmod-qca-nss-ecm=y
# CONFIG_PACKAGE_mwan3 is not set
CONFIG_PACKAGE_luci=y
CONFIG_ATH11K_NSS_SUPPORT=y
"""
        fragment = (base / "candidate.config.fragment").read_text()
        result = module.merge(original, fragment)
        self.assertEqual(result.count("CONFIG_PACKAGE_mwan3=y"), 1)
        self.assertEqual(result.count("CONFIG_PACKAGE_luci=y"), 1)
        self.assertIn("# CONFIG_ATH11K_NSS_SUPPORT is not set", result)
        self.assertNotIn("CONFIG_ATH11K_NSS_SUPPORT=y", result)
        self.assertNotIn("CONFIG_PACKAGE_sing-box=y", result)
        self.assertIn("CONFIG_PACKAGE_luci-theme-argon=y", result)
        self.assertIn("CONFIG_PACKAGE_luci-app-mwan3=y", result)

    def test_rejects_unrelated_build_config(self):
        with self.assertRaises(ValueError):
            module.merge("CONFIG_TARGET_x86=y\n", "CONFIG_PACKAGE_mwan3=y\n")


if __name__ == "__main__":
    unittest.main()
