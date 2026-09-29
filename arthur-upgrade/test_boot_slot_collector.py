import re
import subprocess
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("collect_boot_slot_evidence.sh")


class BootSlotCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text()

    def test_busybox_shell_syntax(self):
        result = subprocess.run(["sh", "-n", str(SCRIPT)], capture_output=True,
                                text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_partition_reads_are_fixed_and_bounded(self):
        self.assertIn("[ \"$BOARD\" = 'ap-cp03-c1' ]", self.source)
        self.assertIn("'2:512' '3:512' '12:512'", self.source)
        self.assertEqual(
            set(re.findall(r"read_partition (/dev/mmcblk0p\d+) ([A-Za-z0-9_.-]+)",
                           self.source)),
            {('/dev/mmcblk0p2', 'BOOTCONFIG-p2.img'),
             ('/dev/mmcblk0p3', 'BOOTCONFIG1-p3.img'),
             ('/dev/mmcblk0p12', 'APPSBLENV-p12.img')})
        self.assertIn('bs=4096 count=64', self.source)
        self.assertIn('[ "$bytes" = 262144 ]', self.source)

    def test_no_mutating_router_commands(self):
        commands = re.findall(r"^[ \t]*([A-Za-z0-9_-]+)(?:[ \t]|$)",
                              self.source, flags=re.MULTILINE)
        forbidden = {'fw_setenv', 'mtd', 'ubiformat', 'blkdiscard', 'sgdisk',
                     'fdisk', 'parted', 'mkfs', 'reboot', 'poweroff', 'halt',
                     'uci', 'opkg', 'apk', 'service'}
        self.assertTrue(forbidden.isdisjoint(commands), forbidden & set(commands))
        self.assertNotRegex(self.source, r"dd\s+[^\n]*of=/dev/")

    def test_private_archive_is_integrity_checked_and_warned(self):
        self.assertIn('sha256sum -c SHA256SUMS.txt', self.source)
        self.assertIn('tar -tzf "$OUT"', self.source)
        self.assertIn('never publish it', self.source)


if __name__ == "__main__":
    unittest.main()
