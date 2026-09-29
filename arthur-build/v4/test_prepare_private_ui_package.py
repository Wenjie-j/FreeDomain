import importlib.util
import json
import pathlib
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "private_package", HERE / "prepare_private_ui_package.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PrivateUiPackageTest(unittest.TestCase):
    def test_packages_only_reviewed_source_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            staged, output = root / "staged", root / "package"
            staged.mkdir()
            for name in module.REQUIRED:
                path = staged / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("reviewed source\n")
            (staged / "OFFLINE-ONLY.json").write_text(json.dumps({
                "candidate_setup_ported": True,
                "candidate_setup_dns_owner_hardened": True,
                "candidate_manager_rollback_hardened": True,
                "archive_sha256": "a" * 64,
                "services_archive_sha256": "b" * 64,
            }))
            report = module.prepare(staged, output)
            self.assertFalse(report["contains_config_or_nodes"])
            self.assertEqual(sorted(p.relative_to(output / "files").as_posix()
                                    for p in (output / "files").rglob("*") if p.is_file()),
                             sorted(module.REQUIRED))
            self.assertFalse((output / "files/etc/config/singbox").exists())
            self.assertIn("+arthur-singbox-firewall4-test",
                          (output / "Makefile").read_text())

    def test_rejects_unported_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "OFFLINE-ONLY.json").write_text("{}")
            with self.assertRaises(ValueError):
                module.prepare(root, root / "output")


if __name__ == "__main__":
    unittest.main()
