import importlib.util
import pathlib
import tempfile
import unittest


HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "validate_package", HERE / "validate_firewall4_test_package.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Firewall4TestPackageTest(unittest.TestCase):
    def test_repository_package_is_non_activating_and_exact(self):
        report = module.validate(
            HERE / "package/arthur-singbox-firewall4-test",
            HERE / "sing-box-firewall4.candidate",
        )
        self.assertEqual(report["status"], "PASS_LAYOUT_ONLY")
        self.assertTrue(all(report["checks"].values()))

    def test_changed_packaged_backend_is_blocked(self):
        package = HERE / "package/arthur-singbox-firewall4-test"
        with tempfile.TemporaryDirectory() as directory:
            candidate = pathlib.Path(directory) / "candidate"
            candidate.write_text("different")
            report = module.validate(package, candidate)
        self.assertEqual(report["status"], "BLOCKED_LAYOUT")
        self.assertFalse(report["checks"]["candidate_bytes_match"])


if __name__ == "__main__":
    unittest.main()
