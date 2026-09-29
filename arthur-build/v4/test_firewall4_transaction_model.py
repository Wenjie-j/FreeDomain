import importlib.util
import pathlib
import unittest


path = pathlib.Path(__file__).with_name("firewall4_transaction_model.py")
spec = importlib.util.spec_from_file_location("transaction", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Adapter:
    def __init__(self, fail=None, blockers=()):
        self.fail = fail
        self.blockers = blockers
        self.calls = []
        self.reload_count = 0

    def preflight(self):
        self._call("preflight")
        return self.blockers

    def fw4_reload(self):
        self.reload_count += 1
        self._call("fw4_reload", "fw4_reload_" + str(self.reload_count))

    def _call(self, name, alternate=None):
        self.calls.append(name)
        if self.fail is not None and self.fail in (name, alternate):
            raise RuntimeError("simulated failure")


for method in ("validate_candidate_offline", "stage_include", "fw4_check", "add_local_route", "add_masked_rule",
               "verify_chains", "remove_include", "restore_include",
               "delete_masked_rule", "delete_local_route", "verify_ownership",
               "verify_chains_absent", "release_ownership"):
    setattr(Adapter, method, lambda self, method=method: self._call(method))


class TransactionModelTest(unittest.TestCase):
    def test_start_checks_before_install_and_verifies_after_reload(self):
        adapter = Adapter()
        result = module.start(adapter)
        self.assertEqual(result["state"], "MODEL_ACTIVE")
        self.assertEqual(adapter.calls, ["preflight", "validate_candidate_offline",
                                         "add_local_route", "add_masked_rule",
                                         "stage_include", "fw4_check",
                                         "fw4_reload", "verify_chains"])
        self.assertFalse(result["activation_approved"])

    def test_preflight_or_syntax_failure_never_enables_live_rules(self):
        blocked = Adapter(blockers=("ROUTING_TABLE_166_NOT_EMPTY",))
        self.assertEqual(module.start(blocked)["state"], "BLOCKED")
        self.assertEqual(blocked.calls, ["preflight"])
        broken = Adapter(fail="validate_candidate_offline")
        self.assertEqual(module.start(broken)["state"], "BLOCKED")
        self.assertNotIn("add_local_route", broken.calls)
        self.assertNotIn("fw4_reload", broken.calls)
        checked = Adapter(fail="fw4_check")
        self.assertEqual(module.start(checked)["state"], "ROLLED_BACK")
        self.assertIn("delete_local_route", checked.calls)
        self.assertNotIn("fw4_reload", checked.calls)
        unavailable = Adapter(fail="preflight")
        self.assertEqual(module.start(unavailable)["state"], "BLOCKED")
        self.assertEqual(unavailable.calls, ["preflight"])

    def test_reload_failure_reloads_without_include_before_removing_route(self):
        adapter = Adapter(fail="fw4_reload_1")
        result = module.start(adapter)
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertEqual(adapter.calls[-4:], ["remove_include", "fw4_reload",
                                             "delete_masked_rule", "delete_local_route"])
        rule_failed = Adapter(fail="add_masked_rule")
        self.assertEqual(module.start(rule_failed)["state"], "ROLLED_BACK")
        self.assertNotIn("fw4_reload", rule_failed.calls)
        self.assertNotIn("delete_masked_rule", rule_failed.calls)
        self.assertIn("delete_local_route", rule_failed.calls)

    def test_failed_rollback_keeps_policy_route_and_restores_include(self):
        adapter = Adapter(fail="fw4_reload")
        result = module.start(adapter)
        self.assertEqual(result["state"], "MANUAL_RECOVERY_REQUIRED_KEEP_ROUTING")
        self.assertIn("restore_include", adapter.calls)
        self.assertNotIn("delete_local_route", adapter.calls)

    def test_stop_only_drops_route_after_verified_firewall_reload(self):
        adapter = Adapter()
        result = module.stop(adapter)
        self.assertEqual(result["state"], "MODEL_INACTIVE")
        self.assertEqual(adapter.calls, ["verify_ownership", "remove_include",
                                         "fw4_reload", "verify_chains_absent",
                                         "delete_masked_rule", "delete_local_route",
                                         "release_ownership"])
        failed = Adapter(fail="fw4_reload")
        self.assertEqual(module.stop(failed)["state"],
                         "MANUAL_RECOVERY_REQUIRED_KEEP_ROUTING")
        self.assertIn("restore_include", failed.calls)
        self.assertNotIn("delete_masked_rule", failed.calls)
        foreign = Adapter(fail="verify_ownership")
        self.assertEqual(module.stop(foreign)["state"], "BLOCKED_NOT_OWNED")
        self.assertEqual(foreign.calls, ["verify_ownership"])


if __name__ == "__main__":
    unittest.main()
