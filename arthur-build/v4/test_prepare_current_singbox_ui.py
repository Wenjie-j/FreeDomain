import importlib.util
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("prepare_current_ui", HERE / "prepare_current_singbox_ui.py")
import sys
sys.path.insert(0, str(HERE))
porter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(porter)


class ControllerPort(unittest.TestCase):
    def test_all_mutations_become_post_only_and_list_stays_get(self):
        routes = ''.join(
            'entry({"admin","services","singbox","api","%s"}, call("api_%s")).leaf=true\n'
            % (action, action) for action in porter.MUTATIONS
        )
        routes += 'entry({"admin","services","singbox","api","list"}, call("api_list")).leaf=true\n'
        routes += 'local function require_post()\n    if not csrf() then\n'
        hardened = porter.harden_controller(routes)
        for action in porter.MUTATIONS:
            self.assertIn('post("api_%s")' % action, hardened)
            self.assertNotIn('call("api_%s")' % action, hardened)
        self.assertIn('call("api_list")', hardened)
        self.assertIn('getenv("REQUEST_METHOD") ~= "POST"', hardened)
        with self.assertRaises(ValueError):
            porter.harden_controller(hardened)


if __name__ == "__main__":
    unittest.main()
