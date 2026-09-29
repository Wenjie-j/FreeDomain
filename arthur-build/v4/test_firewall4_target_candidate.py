import os
import pathlib
import subprocess
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parent


class TargetShellCandidateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        state = self.root / "state"
        include = self.root / "nftables.d/90-arthur-singbox.nft"
        lock = self.root / "lock/transaction"
        source = (HERE / "sing-box-firewall4.candidate").read_text()
        source = source.replace("STATE_DIR=/etc/sing-box/arthur",
                                "STATE_DIR=" + str(state))
        source = source.replace("INCLUDE=/etc/nftables.d/90-arthur-singbox.nft",
                                "INCLUDE=" + str(include))
        source = source.replace("LOCK=/var/lock/arthur-singbox-firewall4.lock",
                                "LOCK=" + str(lock))
        self.script = self.root / "sing-box-firewall4"
        self.script.write_text(source)
        self.script.chmod(0o700)
        state.mkdir()
        candidate = state / "firewall4-candidate.nft"
        candidate.write_text("""set arthur_cn4 { type ipv4_addr; }
chain arthur_singbox_udp {
 meta l4proto udp tproxy ip to :7895 meta mark set mark and 0xffffff00 xor 0x66 accept
}
chain arthur_singbox_tcp_dns { meta l4proto tcp redirect to :7892 }
""")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.runtime = self.root / "runtime"
        self.runtime.mkdir()
        self._command("logger", "exit 0")
        self._command("ip", r'''
case "$*" in
  "-4 rule show")
    echo "0: from all lookup local"
    [ ! -f "$FAKE_STATE/rule" ] || echo "16666: from all fwmark 0x66/0xff lookup 166"
    [ ! -f "$FAKE_STATE/foreign-rule" ] || echo "16666: from all lookup 200"
    ;;
  "-4 route show table 166")
    [ ! -f "$FAKE_STATE/route" ] || echo "local default dev lo scope host"
    [ ! -f "$FAKE_STATE/foreign-route" ] || echo "default via 192.0.2.1 dev eth0"
    ;;
  "-4 route add local 0.0.0.0/0 dev lo table 166") touch "$FAKE_STATE/route" ;;
  "-4 route del local 0.0.0.0/0 dev lo table 166") rm -f "$FAKE_STATE/route" ;;
  "-4 rule add pref 16666 fwmark 0x66/0xff table 166") touch "$FAKE_STATE/rule" ;;
  "-4 rule del pref 16666 fwmark 0x66/0xff table 166") rm -f "$FAKE_STATE/rule" ;;
  *) exit 70 ;;
esac
''')
        self._command("fw4", r'''
case "$1" in
  check) [ -f "$FAKE_INCLUDE" ] ;;
  reload)
    if [ -f "$FAKE_STATE/fail-next-reload" ]; then
      rm -f "$FAKE_STATE/fail-next-reload"
      exit 1
    fi
    if [ -f "$FAKE_INCLUDE" ]; then touch "$FAKE_STATE/chains"; else rm -f "$FAKE_STATE/chains"; fi
    ;;
  *) exit 71 ;;
esac
''')
        self._command("nft", r'''
[ "$1 $2 $3 $4 $5" = "list chain inet fw4 arthur_singbox_udp" ] ||
[ "$1 $2 $3 $4 $5" = "list chain inet fw4 arthur_singbox_tcp_dns" ] || exit 72
[ -f "$FAKE_STATE/chains" ]
''')
        self.env = os.environ.copy()
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env["PATH"]
        self.env["FAKE_STATE"] = str(self.runtime)
        self.env["FAKE_INCLUDE"] = str(include)
        self.include = include

    def _command(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o700)

    def call(self, action):
        return subprocess.run([str(self.script), action], env=self.env,
                              capture_output=True, text=True)

    def test_start_status_stop_transaction(self):
        self.assertEqual(self.call("start").returncode, 0)
        self.assertTrue(self.include.is_file())
        self.assertTrue((self.runtime / "rule").is_file())
        self.assertTrue((self.runtime / "route").is_file())
        self.assertEqual(self.call("status").returncode, 0)
        self.assertEqual(self.call("stop").returncode, 0)
        self.assertFalse(self.include.exists())
        self.assertFalse((self.runtime / "rule").exists())
        self.assertFalse((self.runtime / "route").exists())

    def test_foreign_route_blocks_before_include_write(self):
        (self.runtime / "foreign-route").touch()
        result = self.call("start")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.include.exists())
        self.assertFalse((self.runtime / "rule").exists())

    def test_failed_activation_rolls_back_include_and_routing(self):
        (self.runtime / "fail-next-reload").touch()
        result = self.call("start")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.include.exists())
        self.assertFalse((self.runtime / "rule").exists())
        self.assertFalse((self.runtime / "route").exists())

    def test_repeated_start_restores_volatile_routing_after_reboot(self):
        self.assertEqual(self.call("start").returncode, 0)
        (self.runtime / "rule").unlink()
        (self.runtime / "route").unlink()
        (self.runtime / "chains").unlink()
        self.assertEqual(self.call("start").returncode, 0)
        self.assertTrue((self.runtime / "rule").is_file())
        self.assertTrue((self.runtime / "route").is_file())
        self.assertEqual(self.call("stop").returncode, 0)


if __name__ == "__main__":
    unittest.main()
