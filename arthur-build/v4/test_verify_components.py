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


if __name__ == "__main__":
    unittest.main()
