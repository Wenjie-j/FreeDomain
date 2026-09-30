import importlib.util
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("prepare_cn", HERE / "prepare_cn_firewall_candidate.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SameSourceCnRules(unittest.TestCase):
    def test_uses_exact_srs_input_and_keeps_prior_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            srs = root / "geoip-cn.srs"
            srs.write_bytes(b"test-srs" * 20)
            output = root / "candidate.nft"
            cidrs = [f"11.{n // 65536}.{n // 256 % 256}.{n % 256}/32"
                     for n in range(5000)]

            def fake_decompile(command, **kwargs):
                self.assertEqual(command[1:4], ["rule-set", "decompile", "--output"])
                self.assertEqual(command[-1], str(srs))
                pathlib.Path(command[4]).write_text(json.dumps({"rules": [{"ip_cidr": cidrs}]}))

            with patch.object(module.subprocess, "run", side_effect=fake_decompile):
                report = module.prepare(root / "sing-box", srs, "br-lan",
                                        ["8.8.8.8", "1.1.1.1"], output)
                self.assertEqual(report["source_srs_sha256"], hashlib.sha256(srs.read_bytes()).hexdigest())
                self.assertEqual(report["cn_ipv4_cidr_count"], 5000)
                self.assertEqual(report["proxy_endpoint_ipv4_count"], 2)
                self.assertNotIn("1.1.1.1", json.dumps(report))
                self.assertIn("@arthur_cn4", output.read_text())
                self.assertIn("ip daddr 8.8.8.8 return", output.read_text())
                self.assertEqual(output.read_text().count("ip daddr 1.1.1.1 return"), 2)
                with self.assertRaises(ValueError):
                    module.prepare(root / "sing-box", srs, "br-lan", "8.8.8.8", output)

    def test_dns_expiry_during_decompile_does_not_publish_a_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            srs = root / "geoip-cn.srs"
            srs.write_bytes(b"test-srs" * 20)
            output = root / "new-directory/candidate.nft"
            cidrs = [f"11.{n // 65536}.{n // 256 % 256}.{n % 256}/32"
                     for n in range(5000)]

            def fake_decompile(command, **kwargs):
                pathlib.Path(command[4]).write_text(json.dumps({"rules": [{"ip_cidr": cidrs}]}))

            with patch.object(module.subprocess, "run", side_effect=fake_decompile), \
                    patch.object(module.time, "time", return_value=1200):
                with self.assertRaisesRegex(ValueError, "expired during"):
                    module.prepare(root / "sing-box", srs, "br-lan", "1.1.1.1",
                                   output, endpoint_valid_until=1200)
            self.assertFalse(output.parent.exists())

    def test_failed_conversion_writes_no_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            srs = root / "geoip-cn.srs"
            srs.write_bytes(b"test-srs" * 20)
            output = root / "candidate.nft"
            with patch.object(module.subprocess, "run", side_effect=OSError("unavailable")):
                with self.assertRaises(ValueError):
                    module.prepare(root / "sing-box", srs, "br-lan", "8.8.8.8", output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
