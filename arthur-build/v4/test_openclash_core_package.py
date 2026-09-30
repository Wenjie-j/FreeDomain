import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import prepare_openclash_core as prepare
import report_openclash_core_package as report


class OpenClashCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.elf = bytearray(64)
        self.elf[:7] = b"\x7fELF\x02\x01\x01"
        self.elf[16:20] = b"\x02\x00\xb7\x00"
        self.archive = self.base / "core.tar.gz"
        self.package = self.base / "package"
        self.package.mkdir()
        (self.package / "Makefile").write_text("recipe fixture")

    def archive_fixture(self, name="clash", kind=tarfile.REGTYPE, data=None):
        with tarfile.open(self.archive, "w:gz") as tar:
            info = tarfile.TarInfo(name)
            info.type = kind
            data = bytes(self.elf) if data is None else data
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                info.linkname = "/etc/config/openclash"
            tar.addfile(info, io.BytesIO(data) if info.size else None)
        raw = self.archive.read_bytes()
        return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

    def lock(self, blob):
        return {"openclash_core_source": {
            "repository": prepare.REPOSITORY, "revision": prepare.SOURCE,
            "archive_path": prepare.ARCHIVE_PATH, "git_blob_sha": blob,
        }}

    def test_fixed_source_lock_rejects_different_candidate(self):
        prepare.source_checks(self.lock(prepare.BLOB))
        with self.assertRaises(ValueError):
            prepare.source_checks(self.lock("0" * 40))

    def test_valid_archive_stages_without_execution_and_refuses_overwrite(self):
        blob = self.archive_fixture()
        with patch.object(prepare, "BLOB", blob):
            trace = prepare.prepare(self.archive, self.lock(blob), self.package)
            self.assertTrue(trace["archive_git_blob_verified"])
            self.assertFalse(trace["executed_during_preparation"])
            self.assertEqual((self.package / "files/clash_meta").read_bytes(), self.elf)
            with self.assertRaises(ValueError):
                prepare.prepare(self.archive, self.lock(blob), self.package)

    def test_mismatched_archive_bytes_block(self):
        self.archive_fixture()
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            prepare.read_verified_archive(self.archive, "0" * 40)

    def test_archive_paths_links_and_wrong_architecture_block(self):
        for name, kind, data in (("../clash", tarfile.REGTYPE, self.elf),
                                 ("/clash", tarfile.REGTYPE, self.elf),
                                 ("clash", tarfile.SYMTYPE, None),
                                 ("etc/init.d/openclash", tarfile.REGTYPE, self.elf),
                                 ("clash", tarfile.REGTYPE, b"not ARM64")):
            with self.subTest(name=name, kind=kind):
                blob = self.archive_fixture(name, kind, data)
                with self.assertRaises(ValueError):
                    prepare.read_verified_archive(self.archive, blob)
        wrong_arch = bytearray(self.elf)
        wrong_arch[18:20] = b"\x3e\x00"
        with self.assertRaises(ValueError):
            prepare.validate_arm64_elf(wrong_arch)

    def test_symlink_staging_destination_blocks(self):
        blob = self.archive_fixture()
        (self.package / "files").symlink_to(self.base, target_is_directory=True)
        with patch.object(prepare, "BLOB", blob), self.assertRaises(ValueError):
            prepare.prepare(self.archive, self.lock(blob), self.package)

    def test_audit_records_only_core_and_rejects_collision_extra_files_bad_trace(self):
        root = self.base / "root"
        core = root / report.CORE_PATH
        core.parent.mkdir(parents=True)
        core.write_bytes(self.elf)
        core.chmod(0o755)
        apk = self.base / "arthur-openclash-core-20260930-r1.apk"
        apk.write_bytes(b"apk fixture, not a runtime test")
        config = self.base / "config"
        config.write_text("CONFIG_PACKAGE_arthur-openclash-core=m\n")
        trace = {
            "source_repository": prepare.REPOSITORY, "source_commit": prepare.SOURCE,
            "source_archive_path": prepare.ARCHIVE_PATH, "source_blob_sha": prepare.BLOB,
            "archive_git_blob_verified": True, "archive_sha256": "a" * 64,
            "binary_sha256": hashlib.sha256(self.elf).hexdigest(),
            "binary_size": len(self.elf), "target_arch": "aarch64",
            "executed_during_preparation": False,
        }
        result, owners = report.build_report(root, apk, config, {}, trace)
        self.assertEqual(owners[report.CORE_PATH], [report.PACKAGE])
        self.assertFalse(result["runtime_tested"])
        for existing, record in (({report.CORE_PATH: ["luci-app-openclash"]}, trace),
                                 ({}, {**trace, "binary_sha256": "0" * 64})):
            with self.assertRaises(ValueError):
                report.build_report(root, apk, config, existing, record)
        (root / "etc/config").mkdir()
        (root / "etc/config/openclash").write_text("must not overwrite user configuration")
        with self.assertRaises(ValueError):
            report.build_report(root, apk, config, {}, trace)

    def test_recipe_has_no_service_or_configuration_install(self):
        recipe = Path(__file__).with_name("package") / "arthur-openclash-core/Makefile"
        text = recipe.read_text()
        self.assertIn("DEPENDS:=@aarch64", text)
        self.assertIn("$(1)/etc/openclash/core/clash_meta", text)
        self.assertNotIn("$(1)/etc/config", text)
        self.assertNotIn("$(1)/etc/init.d", text)


if __name__ == "__main__":
    unittest.main()
