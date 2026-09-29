import importlib.util
import pathlib
import sys
import tempfile
import unittest
from types import SimpleNamespace


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("sandbox_adapter", HERE / "firewall4_sandbox_adapter.py")
sandbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sandbox)
from firewall4_transaction_model import reconcile_after_boot, start, stop


class FakeCommands:
    offline_simulation = True

    def __init__(self, root):
        self.root = root
        self.calls = []
        self.route = self.rule = self.active = False
        self.fail_reload_once = False
        self.ip_rules = "0: from all lookup local\n32766: from all lookup main\n"
        self.table_routes = ""
        self.mwan_mask = "0x3f00\n"
        self.foreign_rule = ""
        self.foreign_route = ""

    def __call__(self, args):
        self.calls.append(args)
        command = tuple(args)
        stdout, rc = "", 0
        if command == ("ip", "-4", "rule", "show"):
            stdout = self.ip_rules + self.foreign_rule
            if self.rule:
                stdout += "16666: from all fwmark 0x66/0xff lookup 166\n"
        elif command == ("ip", "-4", "route", "show", "table", "166"):
            stdout = self.table_routes + self.foreign_route
            if self.route:
                stdout += "local default dev lo scope host\n"
        elif command == ("fw4", "print"):
            stdout = "table inet fw4 { chain prerouting {} }"
        elif command == ("uci", "-q", "get", "mwan3.globals.mmx_mask"):
            stdout = self.mwan_mask
        elif command[:3] == ("nft", "-c", "-f"):
            if b"table inet fw4" not in pathlib.Path(args[3]).read_bytes():
                rc = 1
        elif command == ("fw4", "reload"):
            if self.fail_reload_once:
                self.fail_reload_once = False
                rc = 1
            else:
                self.active = (self.root / "etc/nftables.d/90-arthur-singbox.nft").is_file()
        elif command == ("fw4", "check"):
            rc = 0 if (self.root / "etc/nftables.d/90-arthur-singbox.nft").is_file() else 1
        elif command[:4] == ("nft", "list", "chain", "inet"):
            rc = 0 if self.active else 1
        elif command[:4] == ("ip", "-4", "route", "add"):
            self.route = True
        elif command[:4] == ("ip", "-4", "route", "del"):
            if not self.route:
                rc = 2
            else:
                self.route = False
        elif command[:4] == ("ip", "-4", "rule", "add"):
            self.rule = True
        elif command[:4] == ("ip", "-4", "rule", "del"):
            if not self.rule:
                rc = 2
            else:
                self.rule = False
        else:
            raise AssertionError("unexpected fake command: " + repr(command))
        return SimpleNamespace(returncode=rc, stdout=stdout)


class SandboxTransactionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        (self.root / ".offline-router-simulation").touch()
        private = self.root / "private"
        private.mkdir()
        (private / "candidate.nft").write_text("""set arthur_cn4 { type ipv4_addr; }
chain arthur_singbox_udp {
    meta l4proto udp tproxy ip to :7895 meta mark set mark and 0xffffff00 xor 0x66 accept
}
chain arthur_singbox_tcp_dns { tcp dport 53 redirect to :53 }
""")
        self.commands = FakeCommands(self.root)

    def adapter(self):
        return sandbox.SandboxAdapter(self.root, self.commands)

    def test_start_and_stop_new_instance_owns_only_its_include_and_route(self):
        active = start(self.adapter())
        self.assertEqual(active["state"], "MODEL_ACTIVE")
        self.assertTrue(self.commands.route and self.commands.rule and self.commands.active)
        stopped = stop(self.adapter())
        self.assertEqual(stopped["state"], "MODEL_INACTIVE")
        self.assertFalse(self.commands.route or self.commands.rule or self.commands.active)
        self.assertFalse((self.root / "etc/nftables.d/90-arthur-singbox.nft").exists())
        self.assertFalse((self.root / "etc/sing-box/arthur/firewall4-owner.json").exists())

    def test_failed_reload_reverts_include_and_exact_acquired_resources(self):
        self.commands.fail_reload_once = True
        result = start(self.adapter())
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertFalse(self.commands.route or self.commands.rule or self.commands.active)
        self.assertFalse((self.root / "etc/nftables.d/90-arthur-singbox.nft").exists())

    def test_tampered_include_or_unmarked_root_never_stops_foreign_rules(self):
        self.assertEqual(start(self.adapter())["state"], "MODEL_ACTIVE")
        include = self.root / "etc/nftables.d/90-arthur-singbox.nft"
        include.write_text(include.read_text() + "\n# foreign edit\n")
        before = len(self.commands.calls)
        self.assertEqual(stop(self.adapter())["state"], "BLOCKED_NOT_OWNED")
        self.assertEqual(len(self.commands.calls), before)
        self.assertTrue(include.exists())
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(sandbox.AdapterError):
                sandbox.SandboxAdapter(pathlib.Path(directory), self.commands)
        with self.assertRaises(sandbox.AdapterError):
            sandbox.SandboxAdapter(self.root, None)

    def test_existing_table_or_mwan_bits_block_before_any_write(self):
        self.commands.table_routes = "local default dev lo"
        self.commands.mwan_mask = "0x3fff"
        result = start(self.adapter())
        self.assertEqual(result["state"], "BLOCKED")
        self.assertIn("ROUTING_TABLE_166_NOT_EMPTY", result["errors"])
        self.assertIn("MWAN3_MARK_MASK_OVERLAPS_PROXY", result["errors"])
        self.assertFalse(self.commands.route or self.commands.rule)
        self.assertFalse((self.root / "etc/nftables.d/90-arthur-singbox.nft").exists())

    def test_preexisting_symlink_is_not_followed_or_replaced(self):
        directory = self.root / "etc/nftables.d"
        directory.mkdir(parents=True)
        link = directory / "90-arthur-singbox.nft"
        link.symlink_to(self.root / "private/candidate.nft")
        original = (self.root / "private/candidate.nft").read_bytes()
        result = start(self.adapter())
        self.assertEqual(result["state"], "BLOCKED")
        self.assertTrue(link.is_symlink())
        self.assertEqual((self.root / "private/candidate.nft").read_bytes(), original)

    def test_reconcile_after_simulated_reboot_recreates_missing_routing(self):
        self.assertEqual(start(self.adapter())["state"], "MODEL_ACTIVE")
        self.commands.route = self.commands.rule = False  # volatile state lost at boot
        result = reconcile_after_boot(self.adapter())
        self.assertEqual(result["state"], "MODEL_RECONCILED")
        self.assertTrue(self.commands.route and self.commands.rule and self.commands.active)
        self.assertEqual(stop(self.adapter())["state"], "MODEL_INACTIVE")

    def test_stop_after_reboot_before_reconcile_skips_absent_routing(self):
        self.assertEqual(start(self.adapter())["state"], "MODEL_ACTIVE")
        self.commands.route = self.commands.rule = False
        stopped = stop(self.adapter())
        self.assertEqual(stopped["state"], "MODEL_INACTIVE")
        self.assertFalse(self.commands.active)
        self.assertFalse((self.root / "etc/sing-box/arthur/firewall4-owner.json").exists())

    def test_stop_with_foreign_routing_blocks_before_touching_include(self):
        self.assertEqual(start(self.adapter())["state"], "MODEL_ACTIVE")
        self.commands.foreign_route = "default via 192.0.2.1 dev eth0\n"
        result = stop(self.adapter())
        self.assertEqual(result["state"], "MANUAL_RECOVERY_REQUIRED_KEEP_ROUTING")
        self.assertTrue(self.commands.active)
        self.assertTrue((self.root / "etc/nftables.d/90-arthur-singbox.nft").exists())

    def test_reboot_reconciliation_blocks_foreign_table_166_route(self):
        self.assertEqual(start(self.adapter())["state"], "MODEL_ACTIVE")
        self.commands.route = self.commands.rule = False
        self.commands.foreign_route = "default via 192.0.2.1 dev eth0\n"
        before = len(self.commands.calls)
        result = reconcile_after_boot(self.adapter())
        self.assertEqual(result["state"], "BLOCKED_RECONCILIATION")
        self.assertFalse(self.commands.route or self.commands.rule)
        self.assertNotIn(["fw4", "reload"], self.commands.calls[before:])


if __name__ == "__main__":
    unittest.main()
