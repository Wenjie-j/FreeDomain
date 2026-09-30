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


if __name__ == "__main__":
    unittest.main()
