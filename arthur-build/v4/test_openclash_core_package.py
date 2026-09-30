import gzip
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import prepare_openclash_core as prepare
import report_openclash_core_package as report
import smoke_openclash_core as smoke


class OpenClashCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.elf = bytearray(64)
        self.elf[:7] = b"\x7fELF\x02\x01\x01"
        self.elf[16:20] = b"\x02\x00\xb7\x00"
        self.archive = self.base / "core.gz"
        self.package = self.base / "package"
        self.package.mkdir()
        (self.package / "Makefile").write_text("recipe fixture")

    def archive_fixture(self, data=None):
        self.archive.write_bytes(gzip.compress(bytes(self.elf) if data is None else data))
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def lock(self, digest):
        return {"openclash_core_source": {
            "repository": prepare.REPOSITORY, "revision": prepare.SOURCE,
            "version": prepare.VERSION, "archive_path": prepare.ARCHIVE_PATH,
            "archive_sha256": digest, "download_url": prepare.DOWNLOAD_URL,
        }}

    def trace(self):
        return {
            "source_repository": prepare.REPOSITORY, "source_commit": prepare.SOURCE,
            "source_version": prepare.VERSION, "source_archive_path": prepare.ARCHIVE_PATH,
            "archive_sha256_verified": True, "archive_sha256": prepare.ARCHIVE_SHA256,
            "binary_sha256": hashlib.sha256(self.elf).hexdigest(),
            "binary_size": len(self.elf), "target_arch": "aarch64",
            "executed_during_preparation": False,
        }

    def test_fixed_stable_lock_rejects_alpha_or_different_digest(self):
        prepare.source_checks(self.lock(prepare.ARCHIVE_SHA256))
        with self.assertRaises(ValueError):
            prepare.source_checks(self.lock("0" * 64))
        bad = self.lock(prepare.ARCHIVE_SHA256)
        bad["openclash_core_source"]["version"] = "alpha-ge183c58"
        with self.assertRaises(ValueError):
            prepare.source_checks(bad)

    def test_verified_gzip_stages_without_execution_and_refuses_overwrite(self):
        digest = self.archive_fixture()
        with patch.object(prepare, "ARCHIVE_SHA256", digest):
            trace = prepare.prepare(self.archive, self.lock(digest), self.package)
            self.assertTrue(trace["archive_sha256_verified"])
            self.assertFalse(trace["executed_during_preparation"])
            self.assertTrue(prepare.trace_matches(bytes(self.elf), trace))
            self.assertEqual((self.package / "files/clash_meta").read_bytes(), self.elf)
            with self.assertRaises(ValueError):
                prepare.prepare(self.archive, self.lock(digest), self.package)

    def test_mismatched_archive_bytes_block(self):
        self.archive_fixture()
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            prepare.read_verified_archive(self.archive, "0" * 64)

    def test_wrong_architecture_and_decompression_size_limit_block(self):
        wrong = bytearray(self.elf)
        wrong[18:20] = b"\x3e\x00"
        for data in (b"not ELF", wrong):
            digest = self.archive_fixture(data)
            with self.assertRaises(ValueError):
                prepare.read_verified_archive(self.archive, digest)
        digest = self.archive_fixture()
        with patch.object(prepare, "MAX_BINARY", 63), self.assertRaises(ValueError):
            prepare.read_verified_archive(self.archive, digest)

    def test_symlinked_archive_or_staging_directory_block(self):
        digest = self.archive_fixture()
        link = self.base / "link.gz"
        link.symlink_to(self.archive)
        with self.assertRaises(ValueError):
            prepare.read_verified_archive(link, digest)
        (self.package / "files").symlink_to(self.base, target_is_directory=True)
        with patch.object(prepare, "ARCHIVE_SHA256", digest), self.assertRaises(ValueError):
            prepare.prepare(self.archive, self.lock(digest), self.package)

    def test_audit_rejects_collision_extra_files_and_wrong_binary_trace(self):
        root = self.base / "root"
        core = root / report.CORE_PATH
        core.parent.mkdir(parents=True)
        core.write_bytes(self.elf)
        core.chmod(0o755)
        apk = self.base / "arthur-openclash-core-1.19.31-r1.apk"
        apk.write_bytes(b"apk fixture, not a runtime test")
        config = self.base / "config"
        config.write_text("CONFIG_PACKAGE_arthur-openclash-core=m\n")
        trace = self.trace()
        result, owners = report.build_report(root, apk, config, {}, trace)
        self.assertEqual(owners[report.CORE_PATH], [report.PACKAGE])
        self.assertFalse(result["runtime_tested"])
        for existing, record in (({report.CORE_PATH: ["luci-app-openclash"]}, trace),
                                 ({}, {**trace, "binary_sha256": "0" * 64})):
            with self.assertRaises(ValueError):
                report.build_report(root, apk, config, existing, record)
        (root / "etc/config").mkdir()
        (root / "etc/config/openclash").write_text("user configuration must survive")
        with self.assertRaises(ValueError):
            report.build_report(root, apk, config, {}, trace)

    def test_recipe_has_no_service_or_configuration_install(self):
        recipe = Path(__file__).with_name("package") / "arthur-openclash-core/Makefile"
        text = recipe.read_text()
        self.assertIn("DEPENDS:=@aarch64", text)
        self.assertIn("PKG_VERSION:=1.19.31", text)
        self.assertIn("$(1)/etc/openclash/core/clash_meta", text)
        self.assertNotIn("$(1)/etc/config", text)
        self.assertNotIn("$(1)/etc/init.d", text)

    def smoke_binary(self):
        binary = self.base / "core"
        binary.write_bytes(self.elf)
        return binary

    def test_emulation_only_calls_version_and_config_check_with_disabled_listeners(self):
        def runner(command, **kwargs):
            self.assertEqual(command[0], "qemu-aarch64")
            self.assertLessEqual(kwargs["timeout"], 45)
            if command[2] == "-v":
                return subprocess.CompletedProcess(command, 0, "Mihomo Meta v1.19.31 linux arm64", "")
            self.assertEqual(command[2], "-t")
            config = Path(command[-1]).read_text()
            for key in ("port", "mixed-port", "socks-port", "redir-port", "tproxy-port"):
                self.assertIn(key + ": 0", config)
            self.assertIn("proxies: []", config)
            return subprocess.CompletedProcess(command, 0, "configuration file test is successful", "")
        with patch.object(smoke.subprocess, "run", side_effect=runner) as run:
            result = smoke.run_smoke(self.smoke_binary(), self.trace())
            self.assertEqual(run.call_count, 2)
            self.assertFalse(result["proxy_service_started"])
            self.assertFalse(result["router_tested"])

    def test_unverified_core_is_never_executed(self):
        with patch.object(smoke.subprocess, "run") as run, self.assertRaises(ValueError):
            smoke.run_smoke(self.smoke_binary(), {**self.trace(), "binary_sha256": "0" * 64})
        run.assert_not_called()

    def test_wrong_version_and_invalid_configuration_block_smoke(self):
        binary = self.smoke_binary()
        for version in ("alpha-ge183c58", "Mihomo v1.19.310"):
            with patch.object(smoke.subprocess, "run", return_value=
                              subprocess.CompletedProcess([], 0, version, "")) as run:
                with self.assertRaises(ValueError):
                    smoke.run_smoke(binary, self.trace())
                self.assertEqual(run.call_count, 1)
        results = [subprocess.CompletedProcess([], 0, "Mihomo v1.19.31", ""),
                   subprocess.CompletedProcess([], 1, "", "invalid config")]
        with patch.object(smoke.subprocess, "run", side_effect=results), self.assertRaises(ValueError):
            smoke.run_smoke(binary, self.trace())


if __name__ == "__main__":
    unittest.main()
