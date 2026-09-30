import pathlib
import subprocess
import unittest


SCRIPT = pathlib.Path(__file__).with_name("collect_legacy_proxy_evidence.sh")


class LegacyProxyCollectorTest(unittest.TestCase):
    def test_busybox_shell_syntax_and_private_scope(self):
        subprocess.run(["sh", "-n", str(SCRIPT)], check=True)
        source = SCRIPT.read_text()
        self.assertIn("umask 077", source)
        self.assertIn("copy_file /etc/config/singbox", source)
        self.assertIn("copy_file /etc/config/openclash", source)
        self.assertNotIn("copy_tree_files /etc/openclash\n", source)
        self.assertNotIn("/etc/openclash/core", source)
        self.assertNotIn("uci set", source)
        self.assertNotIn("/etc/init.d/", source)
        self.assertNotIn("mmcblk", source)


if __name__ == "__main__":
    unittest.main()
