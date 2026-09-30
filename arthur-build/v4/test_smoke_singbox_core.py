import hashlib
import subprocess
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from smoke_singbox_core import run_smoke, interpreter_path, CORE_SOURCE, CORE_TAGS, V4_BASE
from test_core_elf import synthetic_arm64_elf


class SingboxSmokeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root / "sing-box"
        self.binary.write_bytes(synthetic_arm64_elf())
        self.binary.chmod(0o755)
        self.trace = {"binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                      "base_commit": V4_BASE, "source_commit": CORE_SOURCE,
                      "source_version": "1.14.1", "target_arch_packages": "aarch64_cortex-a53",
                      "build_tags": sorted(CORE_TAGS)}
        self.version = "sing-box version 1.14.1\n\nEnvironment: go1.27 linux/arm64\nTags: " + ",".join(sorted(CORE_TAGS)) + "\n"

    def answers(self, version=None, valid=0, invalid=1, error="unknown outbound type: arthur-invalid-outbound"):
        return [subprocess.CompletedProcess([], 0, self.version if version is None else version, ""),
                subprocess.CompletedProcess([], valid, "", ""),
                subprocess.CompletedProcess([], invalid, "", error)]

    def dynamic_core(self, interpreter=b"/lib/ld-musl-aarch64.so.1\0"):
        data = bytearray(synthetic_arm64_elf())
        data.extend(b"\0" * (256 - len(data)))
        struct.pack_into("<H", data, 56, 2)
        struct.pack_into("<IIQQQQQQ", data, 120, 3, 4, 176, 0, 0,
                         len(interpreter), len(interpreter), 1)
        data[176:176 + len(interpreter)] = interpreter
        self.binary.write_bytes(data)
        self.trace["binary_sha256"] = hashlib.sha256(data).hexdigest()
        return data

    @patch("smoke_singbox_core.subprocess.run")
    def test_dynamic_loader_hash_and_foreign_symlink_rejection(self, run):
        self.dynamic_core()
        loader = self.root / "lib/ld-musl-aarch64.so.1"
        loader.parent.mkdir()
        loader.write_bytes(b"test loader only")
        run.side_effect = self.answers()
        report = run_smoke(self.binary, self.trace, self.root)
        self.assertEqual(report["build_loader_sha256"], hashlib.sha256(loader.read_bytes()).hexdigest())
        loader.unlink()
        loader.symlink_to("/bin/sh")
        run.reset_mock()
        with self.assertRaisesRegex(ValueError, "escapes"):
            run_smoke(self.binary, self.trace, self.root)
        run.assert_not_called()

    def test_unexpected_and_malformed_interpreter_rejected(self):
        for value in (b"/lib/foreign.so\0", b"/lib/ld-musl-aarch64.so.1", b"/lib/ld\0bad\0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                interpreter_path(self.dynamic_core(value))

    @patch("smoke_singbox_core.subprocess.run")
    def test_only_version_and_config_commands_with_clean_environment(self, run):
        run.side_effect = self.answers()
        with patch.dict("os.environ", {"QEMU_LD_PREFIX": "/foreign", "LD_PRELOAD": "/foreign"}):
            report = run_smoke(self.binary, self.trace, self.root)
        self.assertFalse(report["router_tested"])
        self.assertFalse(report["proxy_service_started"])
        self.assertTrue(report["invalid_configuration_rejected"])
        self.assertEqual(len(run.call_args_list), 3)
        for call in run.call_args_list:
            self.assertNotIn("run", call.args[0])
            self.assertNotIn("QEMU_LD_PREFIX", call.kwargs["env"])
            self.assertNotIn("LD_PRELOAD", call.kwargs["env"])
            self.assertEqual(call.kwargs["timeout"], 60)

    @patch("smoke_singbox_core.subprocess.run")
    def test_modified_core_or_trace_never_executes(self, run):
        self.binary.write_bytes(self.binary.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "trace"):
            run_smoke(self.binary, self.trace, self.root)
        run.assert_not_called()

    @patch("smoke_singbox_core.subprocess.run")
    def test_version_prefix_wrong_arch_or_missing_compiled_tags_blocks(self, run):
        for version in (self.version.replace("1.14.1", "1.14.10"),
                        self.version.replace("linux/arm64", "linux/amd64"),
                        self.version.replace("with_quic", "no_quic")):
            with self.subTest(version=version):
                run.side_effect = self.answers(version=version)
                with self.assertRaises(ValueError):
                    run_smoke(self.binary, self.trace, self.root)

    @patch("smoke_singbox_core.subprocess.run")
    def test_config_failure_success_or_crash_on_invalid_input_blocks(self, run):
        for answers in (self.answers(valid=1), self.answers(invalid=0),
                        self.answers(invalid=-11), self.answers(error="loader missing")):
            run.side_effect = answers
            with self.assertRaises(ValueError):
                run_smoke(self.binary, self.trace, self.root)

    @patch("smoke_singbox_core.subprocess.run")
    def test_timeout_does_not_produce_a_success(self, run):
        run.side_effect = subprocess.TimeoutExpired("qemu-aarch64", 60)
        with self.assertRaises(subprocess.TimeoutExpired):
            run_smoke(self.binary, self.trace, self.root)


if __name__ == "__main__":
    unittest.main()
