import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from audit_private_ui_package import inspect, PORT_FLAGS
from prepare_private_ui_package import REQUIRED, prepare


class PrivatePackageAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.staged = Path(self.temp.name) / "staged"
        self.staged.mkdir(mode=0o700)
        for name in REQUIRED:
            file = self.staged / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"synthetic source\n")
        manifest = {
            "classification": "PRIVATE_OFFLINE_UI_SOURCE_NOT_INSTALL_APPROVAL",
            "staged_file_sha256": {name: hashlib.sha256((self.staged / name).read_bytes()).hexdigest()
                                   for name in REQUIRED},
            "archive_sha256": "a" * 64,
            "services_archive_sha256": "b" * 64,
        }
        manifest.update({flag: True for flag in PORT_FLAGS})
        (self.staged / "OFFLINE-ONLY.json").write_text(json.dumps(manifest))
        self.package = Path(self.temp.name) / "package"
        prepare(self.staged, self.package)

    def test_independently_matches_synthetic_package(self):
        report = inspect(self.staged, self.package)
        self.assertEqual(report["reviewed_file_count"], 6)
        self.assertFalse(report["target_package_built"])

    def test_rejects_payload_swap_or_extra_private_config(self):
        file = self.package / "files" / REQUIRED[0]
        file.write_bytes(b"other source\n")
        with self.assertRaisesRegex(ValueError, "source differ"):
            inspect(self.staged, self.package)
        file.write_bytes((self.staged / REQUIRED[0]).read_bytes())
        extra = self.package / "files/etc/config/sing-box"
        extra.parent.mkdir(parents=True)
        extra.write_text("private value")
        with self.assertRaisesRegex(ValueError, "unexpected private package payload"):
            inspect(self.staged, self.package)

    def test_rejects_mutated_recipe_and_claimed_port(self):
        recipe = self.package / "Makefile"
        recipe.write_text(recipe.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "recipe differs"):
            inspect(self.staged, self.package)
        recipe.write_text(recipe.read_text()[:-1])
        manifest = self.staged / "OFFLINE-ONLY.json"
        doc = json.loads(manifest.read_text())
        doc[PORT_FLAGS[-1]] = False
        manifest.write_text(json.dumps(doc))
        with self.assertRaisesRegex(ValueError, "manifests disagree"):
            inspect(self.staged, self.package)


if __name__ == "__main__":
    unittest.main()
