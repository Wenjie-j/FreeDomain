import importlib.util
import json
import pathlib
import tempfile
import unittest

base = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("recipe", base / "prepare_singbox_recipe.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SingBoxRecipeTest(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads((base / "feeds.lock.json").read_text())
        self.old = "\n".join((module.OLD_VERSION, module.OLD_HASH,
                              *(f"config {f}" for f in module.REQUIRED_FEATURES)))

    def test_version_and_archive_hash_are_replaced_together(self):
        updated = module.adapt_makefile(self.old, self.lock)
        self.assertIn("PKG_VERSION:=1.14.1", updated)
        self.assertIn("PKG_HASH:=" + self.lock["sing_box_source"]["codeload_sha256"],
                      updated)

    def test_changed_feed_and_unverified_tar_are_rejected(self):
        with self.assertRaises(ValueError):
            module.adapt_makefile(self.old.replace("1.14.0", "1.14.2"), self.lock)
        with tempfile.TemporaryDirectory() as d:
            bad = pathlib.Path(d) / "wrong.tar.gz"
            bad.write_bytes(b"wrong source")
            with self.assertRaises(ValueError):
                module.verify_archive(bad, self.lock)


if __name__ == "__main__":
    unittest.main()
