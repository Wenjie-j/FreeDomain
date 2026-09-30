import hashlib
import importlib.util
import io
import pathlib
import tarfile
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "proxy_preflight", HERE / "proxy_migration_preflight.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def archive_at(path, payloads):
    sums = "".join(hashlib.sha256(data).hexdigest() + "  " + name + "\n"
                   for name, data in payloads.items()).encode()
    all_files = dict(payloads, **{"SHA256SUMS.txt": sums})
    with tarfile.open(path, "w:gz") as archive:
        for name, data in all_files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


class ProxyMigrationPreflightTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temp.name) / "private.tar.gz"
        self.payloads = {
            "CLASSIFICATION.txt": b"PRIVATE\n",
            "etc/config/singbox": b"config singbox main\n",
            "etc/config/openclash": b"config openclash config\n",
            "etc/sing-box/config.json": b"{}\n",
            "etc/openclash/config/current.yaml": b"proxies: []\n",
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_verified_inventory_stays_blocked_for_runtime_migration(self):
        archive_at(self.path, self.payloads)
        report = module.inspect(self.path)
        self.assertEqual(report["decision"], "BLOCKED_FIRST_MIGRATION")
        self.assertEqual(report["inventory"]["singbox_data_files"], 1)
        self.assertFalse(report["legacy_executable_files_included"])
        self.assertFalse(report["secret_values_emitted"])

    def test_rejects_legacy_elf_and_checksum_tampering(self):
        archive_at(self.path, dict(self.payloads,
                                   **{"etc/sing-box/old-core": b"\x7fELFold"}))
        with self.assertRaisesRegex(ValueError, "legacy executable"):
            module.inspect(self.path)
        archive_at(self.path, self.payloads)
        with tarfile.open(self.path, "r:gz") as archive:
            members = {m.name: archive.extractfile(m).read() for m in archive
                       if m.isfile()}
        members["etc/config/singbox"] = b"changed"
        with tarfile.open(self.path, "w:gz") as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            module.inspect(self.path)


if __name__ == "__main__":
    unittest.main()
