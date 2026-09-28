import json
import pathlib
import unittest

base = pathlib.Path(__file__).parent / "luci-app-arthur-overview"


class ReadOnlyUIContractTest(unittest.TestCase):
    def test_acl_and_menu_are_status_only(self):
        share = base / "root/usr/share"
        acl = json.loads((share / "rpcd/acl.d/luci-app-arthur-overview.json").read_text())
        grants = acl["luci-app-arthur-overview"]
        self.assertNotIn("write", grants)
        self.assertEqual(grants["read"]["ubus"], {
            "mwan3": ["status"], "network.interface": ["dump"],
            "network.wireless": ["status"]})
        menu = json.loads((share / "luci/menu.d/luci-app-arthur-overview.json").read_text())
        self.assertEqual(menu["admin/status/arthur"]["action"]["path"], "arthur/overview")
        self.assertTrue((base / "htdocs/luci-static/resources/view/arthur/overview.js").is_file())

    def test_singbox_fragment_keeps_expected_feature_set(self):
        lines = (pathlib.Path(__file__).parent / "singbox-1.14.1.config.fragment").read_text().splitlines()
        tags = {line.removeprefix("CONFIG_SINGBOX_WITH_").removesuffix("=y").lower()
                for line in lines if line.startswith("CONFIG_SINGBOX_WITH_")}
        self.assertEqual(tags, {"quic", "dhcp", "wireguard", "utls", "clash_api"})


if __name__ == "__main__":
    unittest.main()
