import importlib.util
import pathlib
import unittest


path = pathlib.Path(__file__).with_name("proxy_backend_transaction_model.py")
spec = importlib.util.spec_from_file_location("proxy_switch", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Adapter:
    def __init__(self, active=(), fail=None):
        self.active = set(active)
        self.fail = fail
        self.calls = []

    def _call(self, name):
        self.calls.append(name)
        if self.fail == name:
            raise RuntimeError("simulated")

    def active_backends(self):
        self._call("active_backends")
        return set(self.active)

    def stop_backend(self, backend):
        self._call("stop_" + backend)
        self.active.discard(backend)

    def start_backend(self, backend):
        self._call("start_" + backend)
        self.active.add(backend)

    def validate_target(self, target): self._call("validate_" + target)
    def snapshot_state(self): self._call("snapshot_state")
    def restore_snapshot(self): self._call("restore_snapshot")
    def verify_backend(self, backend): self._call("verify_" + backend)
    def verify_backend_inactive(self, backend): self._call("inactive_" + backend)
    def verify_management_reachable(self): self._call("verify_management")
    def verify_domestic_direct_path(self, backend): self._call("domestic_" + backend)
    def commit_choice(self, target): self._call("commit_" + target)


class ProxyBackendTransactionModelTest(unittest.TestCase):
    def test_switches_exclusively_after_health_and_domestic_path_checks(self):
        adapter = Adapter(active=("openclash",))
        result = module.switch(adapter, "sing-box")
        self.assertEqual(result["state"], "MODEL_SWITCHED")
        self.assertEqual(adapter.active, {"sing-box"})
        self.assertLess(adapter.calls.index("domestic_sing-box"),
                        adapter.calls.index("commit_sing-box"))
        self.assertFalse(result["activation_approved"])

    def test_multiple_active_backends_block_without_mutation(self):
        adapter = Adapter(active=("openclash", "sing-box"))
        result = module.switch(adapter, "disabled")
        self.assertEqual(result["state"],
                         "MANUAL_RECOVERY_REQUIRED_MULTIPLE_ACTIVE")
        self.assertEqual(adapter.calls, ["active_backends"])

    def test_failed_target_health_restores_previous_backend(self):
        adapter = Adapter(active=("openclash",), fail="verify_sing-box")
        result = module.switch(adapter, "sing-box")
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertEqual(adapter.active, {"openclash"})
        self.assertIn("stop_sing-box", adapter.calls)
        self.assertIn("start_openclash", adapter.calls)

    def test_failed_rollback_requires_manual_recovery(self):
        adapter = Adapter(active=("sing-box",), fail="domestic_openclash")
        original_restore = adapter.restore_snapshot
        def broken_restore():
            original_restore()
            raise RuntimeError("rollback")
        adapter.restore_snapshot = broken_restore
        result = module.switch(adapter, "openclash")
        self.assertEqual(result["state"], "MANUAL_RECOVERY_REQUIRED")

    def test_disable_stops_backend_then_commits_choice(self):
        adapter = Adapter(active=("sing-box",))
        result = module.switch(adapter, "disabled")
        self.assertEqual(result["state"], "MODEL_SWITCHED")
        self.assertFalse(adapter.active)
        self.assertLess(adapter.calls.index("inactive_sing-box"),
                        adapter.calls.index("commit_disabled"))

    def test_partial_start_failure_is_cleaned_before_previous_restart(self):
        adapter = Adapter(active=("openclash",))
        start = adapter.start_backend
        def partial_start(backend):
            start(backend)
            if backend == "sing-box":
                raise RuntimeError("started but readiness timed out")
        adapter.start_backend = partial_start
        result = module.switch(adapter, "sing-box")
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertEqual(adapter.active, {"openclash"})
        self.assertLess(adapter.calls.index("inactive_sing-box"),
                        adapter.calls.index("start_openclash"))
        self.assertIn("domestic_openclash", adapter.calls)

    def test_partial_stop_failure_recovers_previous_backend(self):
        adapter = Adapter(active=("sing-box",))
        stop = adapter.stop_backend
        def partial_stop(backend):
            stop(backend)
            raise RuntimeError("stopped but cleanup failed")
        adapter.stop_backend = partial_stop
        result = module.switch(adapter, "openclash")
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertEqual(adapter.active, {"sing-box"})
        self.assertNotIn("start_openclash", adapter.calls)

    def test_stop_failure_before_mutation_does_not_start_duplicate_previous(self):
        adapter = Adapter(active=("sing-box",), fail="stop_sing-box")
        result = module.switch(adapter, "openclash")
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertEqual(adapter.active, {"sing-box"})
        self.assertNotIn("start_sing-box", adapter.calls)

    def test_failed_target_that_remains_active_prevents_previous_restart(self):
        adapter = Adapter(active=("openclash",), fail="verify_sing-box")
        # Allow the initial stop, but simulate a target stop returning success
        # while leaving its process/rules active during rollback.
        def stop(backend):
            adapter._call("stop_" + backend)
            if backend == "openclash":
                adapter.active.discard(backend)
        adapter.stop_backend = stop
        result = module.switch(adapter, "sing-box")
        self.assertEqual(result["state"], "MANUAL_RECOVERY_REQUIRED")
        self.assertNotIn("start_openclash", adapter.calls)
        self.assertNotIn("restore_snapshot", adapter.calls)

    def test_snapshot_restore_cannot_activate_a_conflicting_backend(self):
        adapter = Adapter(active=("openclash",), fail="verify_sing-box")
        def restore():
            adapter._call("restore_snapshot")
            adapter.active.add("sing-box")
        adapter.restore_snapshot = restore
        result = module.switch(adapter, "sing-box")
        self.assertEqual(result["state"], "MANUAL_RECOVERY_REQUIRED")
        self.assertNotIn("start_openclash", adapter.calls)

    def test_unhealthy_domestic_path_after_rollback_is_not_reported_as_recovered(self):
        adapter = Adapter(active=("openclash",), fail="verify_sing-box")
        def domestic(backend):
            adapter._call("domestic_" + backend)
            raise RuntimeError("domestic traffic unexpectedly proxied")
        adapter.verify_domestic_direct_path = domestic
        result = module.switch(adapter, "sing-box")
        self.assertEqual(result["state"], "MANUAL_RECOVERY_REQUIRED")

    def test_failed_switch_from_disabled_verifies_management_after_cleanup(self):
        adapter = Adapter(fail="verify_sing-box")
        result = module.switch(adapter, "sing-box")
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertFalse(adapter.active)
        self.assertIn("verify_management", adapter.calls)

    def test_disable_checks_management_and_rolls_back_if_it_is_unreachable(self):
        adapter = Adapter(active=("sing-box",))
        attempts = []
        def management():
            adapter._call("verify_management")
            attempts.append(True)
            if len(attempts) == 1:
                raise RuntimeError("management unreachable")
        adapter.verify_management_reachable = management
        result = module.switch(adapter, "disabled")
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertEqual(adapter.active, {"sing-box"})
        self.assertNotIn("commit_disabled", adapter.calls)


if __name__ == "__main__":
    unittest.main()
