import importlib.util
import pathlib
import unittest


path = pathlib.Path(__file__).with_name("check_firewall4_mark_space.py")
spec = importlib.util.spec_from_file_location("mark_space", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CollisionScreenTest(unittest.TestCase):
    def test_default_mwan_mask_is_disjoint_but_never_approves_activation(self):
        report = module.check("0: from all lookup local\n32766: from all lookup main\n",
                              "", "table inet fw4 { chain prerouting {} }", "0x3F00")
        self.assertEqual(report["blockers"], [])
        self.assertFalse(report["activation_approved"])

    def test_existing_marks_and_table_collisions_block(self):
        rules = "100: from all fwmark 0x66/0xff lookup 166\n"
        report = module.check(rules, "local default dev lo", "chain arthur_singbox_udp {}",
                              "0xff00")
        self.assertIn("EXISTING_FWMARK_USES_PROXY_BITS", report["blockers"])
        self.assertIn("ROUTING_TABLE_166_ALREADY_REFERENCED", report["blockers"])
        self.assertIn("ROUTING_TABLE_166_NOT_EMPTY", report["blockers"])
        self.assertIn("PROXY_FIREWALL_OBJECT_ALREADY_PRESENT", report["blockers"])

    def test_missing_or_overlapping_mwan_mask_fails_closed(self):
        self.assertIn("MWAN3_MARK_MASK_NOT_CAPTURED", module.check("", "", "")["blockers"])
        self.assertIn("MWAN3_MARK_MASK_OVERLAPS_PROXY",
                      module.check("", "", "", "0x3fff")["blockers"])
        self.assertIn("UNPARSEABLE_EXISTING_FWMARK_RULE",
                      module.check("100: fwmark unknown lookup 100", "", "", "0x3f00")["blockers"])


if __name__ == "__main__":
    unittest.main()
