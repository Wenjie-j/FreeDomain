import importlib.util
import hashlib
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
    def make_stage(self, staged):
        staged.mkdir()
        for name in module.REQUIRED:
            path = staged / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("reviewed source\n")
        (staged / "OFFLINE-ONLY.json").write_text(json.dumps({
            "classification": "PRIVATE_OFFLINE_UI_SOURCE_NOT_INSTALL_APPROVAL",
            "candidate_controller_method_hardened": True,
            "candidate_status_ported": True,
            "candidate_setup_ported": True,
            "candidate_setup_dns_owner_hardened": True,
            "candidate_manager_rollback_hardened": True,
            "candidate_manager_stop_checked": True,
            "staged_file_sha256": {
                name: hashlib.sha256((staged / name).read_bytes()).hexdigest()
                for name in module.REQUIRED
            },
            "archive_sha256": "a" * 64,
            "services_archive_sha256": "b" * 64,
        }))

    def test_packages_only_reviewed_source_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            staged, output = root / "staged", root / "package"
            self.make_stage(staged)
            report = module.prepare(staged, output)
            self.assertFalse(report["contains_config_or_nodes"])
            self.assertEqual(sorted(p.relative_to(output / "files").as_posix()
                                    for p in (output / "files").rglob("*") if p.is_file()),
                             sorted(module.REQUIRED))
            self.assertFalse((output / "files/etc/config/singbox").exists())
            self.assertIn("+arthur-singbox-firewall4-test",
                          (output / "Makefile").read_text())

    def test_modified_source_blocks_before_any_output_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            staged, output = root / "staged", root / "package"
            self.make_stage(staged)
            (staged / module.REQUIRED[-1]).write_text("modified service\n")
            with self.assertRaisesRegex(ValueError, "differs"):
                module.prepare(staged, output)
            self.assertFalse(output.exists())

    def test_symlinked_source_manifest_or_output_cannot_follow_foreign_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            staged, output = root / "staged", root / "package"
            self.make_stage(staged)
            file = staged / module.REQUIRED[0]
            foreign = root / "foreign"
            foreign.write_bytes(file.read_bytes())
            file.unlink()
            file.symlink_to(foreign)
            with self.assertRaisesRegex(ValueError, "symlinked"):
                module.prepare(staged, output)
            file.unlink()
            file.write_bytes(foreign.read_bytes())
            empty = root / "empty"
            empty.mkdir()
            output.symlink_to(empty, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "output"):
                module.prepare(staged, output)
            self.assertEqual(list(empty.iterdir()), [])
            output.unlink()
            manifest = staged / "OFFLINE-ONLY.json"
            saved = root / "saved-manifest"
            saved.write_bytes(manifest.read_bytes())
            manifest.unlink()
            manifest.symlink_to(saved)
            with self.assertRaisesRegex(ValueError, "manifest"):
                module.prepare(staged, output)

    def test_old_manifest_without_prepared_file_digests_requires_restaging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            staged = root / "staged"
            self.make_stage(staged)
            file = staged / "OFFLINE-ONLY.json"
            manifest = json.loads(file.read_text())
            del manifest["staged_file_sha256"]
            file.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "digest manifest"):
                module.prepare(staged, root / "output")

    def test_rejects_unported_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "OFFLINE-ONLY.json").write_text("{}")
            with self.assertRaises(ValueError):
                module.prepare(root, root / "output")


if __name__ == "__main__":
    unittest.main()
