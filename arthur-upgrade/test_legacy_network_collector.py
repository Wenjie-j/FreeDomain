import re
import subprocess
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("collect_legacy_network_evidence.sh")


class LegacyNetworkCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text()

    def test_busybox_shell_syntax(self):
        result = subprocess.run(["sh", "-n", str(SCRIPT)], capture_output=True,
                                text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fixed_board_and_read_only_inventory(self):
        self.assertIn("[ \"$BOARD\" = 'ap-cp03-c1' ]", self.source)
        self.assertIn("uci -q show network", self.source)
        for item in ("ip -details -o link show", "ip -4 route show table all",
                     "ubus call network.interface dump", "/etc/board.json"):
            self.assertIn(item, self.source)
        self.assertNotIn("/dev/mmc", self.source)
        self.assertNotRegex(self.source, r"\bdd\s+if=")

    def test_no_mutating_router_commands(self):
        forbidden = (
            r"\buci\s+(?:set|add|delete|rename|reorder|commit|revert|import|batch)\b",
            r"\bip\s+(?:link|address|route|rule)\s+(?:add|del|delete|replace|set|flush)\b",
            r"\b(?:fw_setenv|mtd|ubiformat|blkdiscard|sgdisk|fdisk|parted|mkfs|"
            r"reboot|poweroff|halt|sysupgrade|firstboot|jffs2reset)\b",
            r"\b(?:service|\/etc\/init\.d\/[^ ]+)\s+(?:start|stop|restart|reload)\b",
        )
        for pattern in forbidden:
            self.assertNotRegex(self.source, pattern)

    def test_private_archive_is_integrity_checked_and_warned(self):
        self.assertRegex(
            self.source,
            re.escape('OUT="/tmp/Arthur-Legacy-Network-Evidence-${STAMP}.tar.gz"'))
        self.assertIn('sha256sum -c SHA256SUMS.txt', self.source)
        self.assertIn('tar -tzf "$OUT"', self.source)
        self.assertIn('never publish it', self.source)
        self.assertIn('never prints the contents to the terminal', self.source)


if __name__ == "__main__":
    unittest.main()

