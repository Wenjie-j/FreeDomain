import importlib.util
import json
import pathlib
import unittest

base = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("feeds", base / "write_pinned_feeds.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FeedLockTest(unittest.TestCase):
    def test_every_candidate_is_a_full_immutable_commit(self):
        lock = json.loads((base / "feeds.lock.json").read_text(encoding="utf-8"))
        lines = module.generate(lock).splitlines()
        self.assertEqual(len(lines), 9)
        self.assertTrue(lines[-1].startswith("src-git argon "))
        self.assertTrue(all("^" in line for line in lines[1:]))

    def test_refuses_unreviewed_url(self):
        lock = json.loads((base / "feeds.lock.json").read_text(encoding="utf-8"))
        lock["feeds"][0]["repository"] = "file:///tmp/private"
        with self.assertRaises(ValueError):
            module.generate(lock)


if __name__ == "__main__":
    unittest.main()
