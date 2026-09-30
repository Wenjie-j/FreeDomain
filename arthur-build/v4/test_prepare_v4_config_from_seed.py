import importlib.util
import pathlib
import sys
import unittest

base = pathlib.Path(__file__).parent
sys.path.insert(0, str(base))
spec = importlib.util.spec_from_file_location("seed", base / "prepare_v4_config_from_seed.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SeedConfigTest(unittest.TestCase):
    def test_target_and_core_replace_seed_defaults_once(self):
        seed = """CONFIG_TARGET_qualcommax=y
CONFIG_TARGET_qualcommax_ipq807x=y
CONFIG_PACKAGE_kmod-qca-nss-drv=y
# CONFIG_NSS_FIRMWARE_VERSION_11_4 is not set
# NSS seed
"""
        result = module.prepare(seed, (base / "candidate.config.fragment").read_text(),
                                (base / "singbox-1.14.1.config.fragment").read_text())
        self.assertEqual(result.splitlines().count("CONFIG_PACKAGE_sing-box=y"), 1)
        self.assertEqual(result.splitlines().count("CONFIG_PACKAGE_kmod-nft-tproxy=y"), 1)
        self.assertEqual(result.splitlines().count(
            "CONFIG_PACKAGE_luci-app-openclash=y"), 1)
        self.assertEqual(result.splitlines().count(
            "CONFIG_PACKAGE_arthur-openclash-core=y"), 1)
        self.assertEqual(result.splitlines().count(
            "CONFIG_PACKAGE_luci-app-arthur-overview=y"), 1)
        self.assertEqual(result.splitlines().count(
            "CONFIG_PACKAGE_arthur-openclash-core=m"), 0)
        self.assertEqual(result.splitlines().count(
            "CONFIG_PACKAGE_luci-app-arthur-overview=m"), 0)
        self.assertEqual(result.splitlines().count(
            "CONFIG_PACKAGE_arthur-singbox-firewall4-test=m"), 1)
        self.assertEqual(result.splitlines().count("CONFIG_PACKAGE_iptables-nft=y"), 1)
        self.assertIn("# CONFIG_PACKAGE_iptables-zz-legacy is not set", result)
        self.assertIn("# CONFIG_TARGET_qualcommax_ipq807x is not set", result)
        self.assertNotIn("CONFIG_TARGET_qualcommax_ipq807x=y", result)
        self.assertIn("CONFIG_NSS_FIRMWARE_VERSION_11_4=y", result)
        self.assertIn("# CONFIG_ATH11K_NSS_SUPPORT is not set", result)

    def test_rejects_unrelated_seed(self):
        with self.assertRaises(ValueError):
            module.prepare("CONFIG_TARGET_x86=y\n", "", "")


if __name__ == "__main__":
    unittest.main()
