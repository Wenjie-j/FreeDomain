import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
import zipfile

path = pathlib.Path(__file__).with_name("verify_components.py")
spec = importlib.util.spec_from_file_location("components", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CoreOriginTest(unittest.TestCase):
    def test_openclash_core_trace_uses_locked_archive(self):
        lock = json.loads(path.with_name("feeds.lock.json").read_text())
        core = lock["openclash_core_source"]
        self.assertEqual(core["repository"],
                         "https://github.com/vernesong/OpenClash.git")
        self.assertEqual(core["archive_path"], "master/meta/clash-linux-arm64.tar.gz")
        self.assertEqual(core["revision"], module.OPENCLASH_CORE_SOURCE)
        self.assertEqual(core["git_blob_sha"], module.OPENCLASH_CORE_BLOB)

    def test_core_binary_and_custom_service_must_have_separate_package_owners(self):
        owners = {"usr/bin/sing-box": ["sing-box"]}
        owners.update({path: ["arthur-singbox-service"]
                       for path in module.CUSTOM_OWNED_FILES})
        owners["etc/openclash/core/clash_meta"] = ["arthur-openclash-core"]
        self.assertTrue(all(module.package_ownership_checks(owners).values()))

        owners["etc/init.d/sing-box"] = ["sing-box"]
        checks = module.package_ownership_checks(owners)
        self.assertFalse(checks["custom_files_not_owned_by_core"])
        self.assertFalse(checks["custom_files_have_separate_owner"])
        del owners["etc/init.d/sing-box"]
        self.assertFalse(module.package_ownership_checks(owners)
                         ["custom_files_have_separate_owner"])
        with self.assertRaises(ValueError):
            module.package_ownership_checks({"usr/bin/sing-box": "sing-box"})
        owners["etc/openclash/core/clash_meta"] = ["luci-app-openclash"]
        self.assertFalse(module.package_ownership_checks(owners)
                         ["openclash_core_owned_separately"])

    def test_legacy_firewall_and_setup_cannot_satisfy_backend_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            sources = {
                "usr/lib/lua/luci/controller/singbox.lua": 'call("api_active")',
                "etc/init.d/sing-box-setup": '/usr/bin/sing-box-firewall start',
                "usr/lib/lua/luci/model/cbi/singbox_status.lua": 'iptables -t nat',
                "usr/bin/sing-box-firewall4": 'HY2_IP="123.45.67.89"\niptables -A X',
            }
            for name, content in sources.items():
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(content)
            checks = module.backend_port_checks(root)
            self.assertTrue(all(value is False for value in checks.values()))
            self.assertNotIn("123.45.67.89", json.dumps(checks))

    def test_old_firmware_binary_cannot_pass_by_name_or_version(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp) / "root"
            for name in module.REQUIRED_ROOT_FILES:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"old-firmware-build")
            archive = pathlib.Path(temp) / "image.zip"
            packages = sorted({p for group in module.REQUIRED_PACKAGES.values() for p in group})
            config = "\n".join((
                "CONFIG_TARGET_qualcommax_ipq60xx_DEVICE_jdcloud_re-ss-01=y",
                "CONFIG_ATH11K_MEM_PROFILE_1G=y",
                "CONFIG_LUCI_LANG_zh_Hans=y",
                "CONFIG_NSS_FIRMWARE_VERSION_11_4=y",
            ))
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("jdcloud_re-ss-01.manifest",
                           "\n".join(f"{p} - 1" for p in packages))
                z.writestr("final.config", config)
            missing = module.inspect(archive, root)
            self.assertEqual(missing["core_build_trace"], "MISSING_V4_BUILD_TRACE")
            self.assertEqual(missing["openclash_core_trace"], "MISSING_OPENCLASH_CORE_TRACE")
            self.assertEqual(missing["package_file_ownership"]["core_binary_owned_by_core"],
                             "NOT_INSPECTED")
            self.assertEqual(missing["component_gate"], "BLOCKED_INCOMPLETE_COMPONENTS")
            claimed_old = {
                "base_commit": "old-linux-4.4", "source_commit": module.CORE_SOURCE,
                "source_version": "1.14.1", "target_arch_packages": "aarch64_cortex-a53",
                "build_tags": sorted(module.CORE_TAGS),
                "binary_sha256": hashlib.sha256(b"old-firmware-build").hexdigest(),
            }
            result = module.inspect(archive, root, claimed_old)
            self.assertEqual(result["core_build_trace"], "INVALID_V4_BUILD_TRACE")
            self.assertEqual(result["component_gate"], "BLOCKED_INCOMPLETE_COMPONENTS")
            claimed_old["base_commit"] = module.V4_BASE
            claimed_old["binary_sha256"] = "0" * 64
            result = module.inspect(archive, root, claimed_old)
            self.assertEqual(result["core_build_trace"], "INVALID_V4_BUILD_TRACE")

    def test_openclash_core_requires_pinned_trace_arm64_elf_and_separate_owner(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp) / "root"
            binary = root / "etc/openclash/core/clash_meta"
            binary.parent.mkdir(parents=True)
            arm64_elf = bytearray(64)
            arm64_elf[:7] = b"\x7fELF\x02\x01\x01"
            arm64_elf[16:18] = b"\x02\x00"
            arm64_elf[18:20] = b"\xb7\x00"
            binary.write_bytes(arm64_elf)
            archive = pathlib.Path(temp) / "image.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("jdcloud_re-ss-01.manifest", "")
                z.writestr("final.config", "")
            trace = {
                "source_repository": "https://github.com/vernesong/OpenClash.git",
                "source_commit": module.OPENCLASH_CORE_SOURCE,
                "source_blob_sha": module.OPENCLASH_CORE_BLOB,
                "target_arch": "aarch64",
                "binary_sha256": hashlib.sha256(arm64_elf).hexdigest(),
            }
            check = lambda report: module.inspect(
                archive, root, openclash_core_build_report=report)
            self.assertEqual(check(trace)["openclash_core_trace"],
                             "MATCHES_DECLARED_OPENCLASH_CORE_TRACE")
            self.assertEqual(check(trace)["component_gate"],
                             "BLOCKED_INCOMPLETE_COMPONENTS")
            for field, wrong in (("source_commit", "0" * 40),
                                 ("source_blob_sha", "0" * 40),
                                 ("target_arch", "x86_64"),
                                 ("binary_sha256", "0" * 64)):
                with self.subTest(field=field):
                    self.assertEqual(check({**trace, field: wrong})
                                     ["openclash_core_trace"],
                                     "INVALID_OPENCLASH_CORE_TRACE")
            binary.write_bytes(b"not an ELF")
            self.assertEqual(check({**trace, "binary_sha256":
                                    hashlib.sha256(b"not an ELF").hexdigest()})
                             ["openclash_core_trace"],
                             "INVALID_OPENCLASH_CORE_TRACE")


if __name__ == "__main__":
    unittest.main()
