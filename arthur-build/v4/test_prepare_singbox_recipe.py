import importlib.util
import json
import pathlib
import subprocess
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
                              *(f"config {f}" for f in module.REQUIRED_FEATURES),
                              module.OLD_CONFFILES, module.OLD_INSTALL,
                              "Package/sing-box-tiny/install=$(Package/sing-box/install)"))

    def test_version_and_archive_hash_are_replaced_together(self):
        updated = module.adapt_makefile(self.old, self.lock)
        self.assertIn("PKG_VERSION:=1.14.1", updated)
        self.assertIn("PKG_HASH:=" + self.lock["sing_box_source"]["codeload_sha256"],
                      updated)
        self.assertIn(module.CORE_INSTALL, updated)
        self.assertNotIn("/etc/init.d/sing-box", updated)
        self.assertNotIn("/etc/config/sing-box", updated)
        self.assertNotIn("/etc/sing-box/", updated)
        self.assertIn("Package/sing-box-tiny/install=$(Package/sing-box/install)", updated)

    def test_changed_service_install_requires_review(self):
        with self.assertRaisesRegex(ValueError, "service/config install changed"):
            module.adapt_makefile(self.old.replace("sing-box.init", "custom.init"), self.lock)

    def test_changed_feed_and_unverified_tar_are_rejected(self):
        with self.assertRaises(ValueError):
            module.adapt_makefile(self.old.replace("1.14.0", "1.14.2"), self.lock)
        with tempfile.TemporaryDirectory() as d:
            bad = pathlib.Path(d) / "wrong.tar.gz"
            bad.write_bytes(b"wrong source")
            with self.assertRaises(ValueError):
                module.verify_archive(bad, self.lock)

    def test_checkout_verifies_tag_commit_and_go_mod_without_worktree_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            def git(*args):
                return subprocess.run(["git", "-C", str(root), *args], check=True,
                                      capture_output=True, text=True).stdout.strip()
            git("init", "-q")
            (root / "go.mod").write_text("module github.com/sagernet/sing-box\n\ngo 1.25.5\n")
            git("add", "go.mod")
            git("-c", "user.name=Arthur Test", "-c", "user.email=test@example.invalid",
                "commit", "-qm", "source fixture")
            git("tag", "v1.14.1")
            lock = json.loads(json.dumps(self.lock))
            lock["sing_box_source"]["revision"] = git("rev-parse", "HEAD")
            (root / "go.mod").unlink()
            module.verify_checkout(root, lock)
            (root / "go.mod").write_text("go 1.24.0\n")
            git("add", "go.mod")
            git("-c", "user.name=Arthur Test", "-c", "user.email=test@example.invalid",
                "commit", "-qm", "wrong revision")
            with self.assertRaises(ValueError):
                module.verify_checkout(root, lock)


if __name__ == "__main__":
    unittest.main()
