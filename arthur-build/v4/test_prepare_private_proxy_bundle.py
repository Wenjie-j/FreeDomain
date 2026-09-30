import hashlib
import json
import pathlib
import tempfile
import time
import unittest
from unittest.mock import patch

import prepare_private_proxy_bundle as bundle


class PrivateRuleBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.binary = self.root / "sing-box"
        self.binary.write_bytes(b"synthetic conversion binary")
        self.binary.chmod(0o700)
        self.srs = self.root / "geoip-cn.srs"
        self.srs.write_bytes(b"synthetic srs" * 12)
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "selector", "outbounds": ["primary", "backup"]},
            {"type": "vless", "tag": "primary", "server": "edge.example",
             "server_port": 443, "password": "private-synthetic-password"},
            {"type": "trojan", "tag": "backup", "server": "8.8.8.8",
             "server_port": 443}]}))
        self.now = int(time.time())
        self.snapshot = self.root / "snapshot.json"
        self.snapshot.write_text(json.dumps({
            "config_sha256": hashlib.sha256(self.config.read_bytes()).hexdigest(),
            "captured_at": self.now,
            "records": {"edge.example": {
                "ipv4": ["1.1.1.1", "9.9.9.9"], "expires_at": self.now + 300}}}))
        self.output = self.root / "private-review"
        self.cidrs = [f"11.{n // 65536}.{n // 256 % 256}.{n % 256}/32"
                      for n in range(5000)]
        self.calls = 0

    def fake_decompile(self, command, **kwargs):
        self.calls += 1
        self.assertEqual(command[1:4], ["rule-set", "decompile", "--output"])
        pathlib.Path(command[4]).write_text(json.dumps({"rules": [
            {"ip_cidr": self.cidrs}]}))

    def build(self, snapshot=True):
        return bundle.build(self.binary, self.srs, self.config,
                            self.snapshot if snapshot else None,
                            "br-lan", self.output)

    def assert_not_published(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob(".arthur-private-review-*")))

    def test_all_private_sources_bound_and_draft_independently_reproduced(self):
        with patch.object(bundle.prepare.__globals__["subprocess"], "run",
                          side_effect=self.fake_decompile):
            report = self.build()
            self.assertEqual(self.calls, 2)
            self.assertEqual(report["source_file_count"], 3)
            self.assertEqual(report["proxy_endpoint_ipv4_count"], 3)
            self.assertFalse(report["router_install_approved"])
            self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
            manifest = json.loads((self.output / bundle.MANIFEST).read_text())
            self.assertEqual(manifest["config_sha256"],
                             hashlib.sha256(self.config.read_bytes()).hexdigest())
            self.assertEqual(set(manifest["payload_sha256"]),
                             {bundle.CONFIG, bundle.SNAPSHOT, bundle.CN_SRS, bundle.NFT})
            self.assertEqual((self.output / bundle.CONFIG).read_bytes(),
                             self.config.read_bytes())
            self.assertEqual((self.output / bundle.SNAPSHOT).read_bytes(),
                             self.snapshot.read_bytes())
            for file in self.output.iterdir():
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            nft = (self.output / bundle.NFT).read_text()
            for address in ("1.1.1.1", "9.9.9.9", "8.8.8.8"):
                self.assertEqual(nft.count(f"ip daddr {address} return"), 2)
            for secret in ("private-synthetic-password", "edge.example", "8.8.8.8", "1.1.1.1"):
                self.assertNotIn(secret, json.dumps(report))
            reviewed = bundle.audit(self.output, self.binary, reproduce=True)
            self.assertTrue(reviewed["rule_bytes_reproduced"])
            self.assertFalse(reviewed["target_service_checked"])

    def test_modified_candidate_fails_even_if_attacker_rewrites_manifest_digest(self):
        with patch.object(bundle.prepare.__globals__["subprocess"], "run",
                          side_effect=self.fake_decompile):
            self.build()
            nft = self.output / bundle.NFT
            nft.write_bytes(nft.read_bytes() + b"\n# unreviewed change\n")
            manifest = self.output / bundle.MANIFEST
            old = json.loads(manifest.read_text())
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                bundle.audit(self.output, self.binary)
            old["payload_sha256"][bundle.NFT] = hashlib.sha256(nft.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(old))
            manifest.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "reproduction differs"):
                bundle.audit(self.output, self.binary)

    def test_replaced_snapshot_or_core_blocks_reuse(self):
        with patch.object(bundle.prepare.__globals__["subprocess"], "run",
                          side_effect=self.fake_decompile):
            self.build()
            core = self.binary.read_bytes()
            self.binary.write_bytes(b"other synthetic binary")
            with self.assertRaisesRegex(ValueError, "converter binary"):
                bundle.audit(self.output, self.binary, reproduce=False)
            self.binary.write_bytes(core)
            snapshot = self.output / bundle.SNAPSHOT
            snapshot.write_bytes(snapshot.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                bundle.audit(self.output, self.binary, reproduce=False)

    def test_expired_domain_snapshot_and_changed_input_leave_no_partial_bundle(self):
        original = self.snapshot.read_bytes()
        stale = json.loads(original)
        stale["records"]["edge.example"]["expires_at"] = self.now - 1
        self.snapshot.write_text(json.dumps(stale))
        with self.assertRaises(ValueError):
            self.build()
        self.assert_not_published()
        self.snapshot.write_bytes(original)
        def mutate_config(command, **kwargs):
            self.fake_decompile(command, **kwargs)
            self.config.write_bytes(self.config.read_bytes() + b" ")
        with patch.object(bundle.prepare.__globals__["subprocess"], "run",
                          side_effect=mutate_config):
            with self.assertRaisesRegex(ValueError, "input changed"):
                self.build()
        self.assert_not_published()

    def test_failed_conversion_preserves_previous_directory(self):
        self.output.mkdir(mode=0o700)
        (self.output / "previous.txt").write_text("keep this")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.build()
        self.assertEqual((self.output / "previous.txt").read_text(), "keep this")
        self.output.rename(self.root / "previous-private-review")
        with patch.object(bundle.prepare.__globals__["subprocess"], "run",
                          side_effect=OSError("synthetic decode failure")):
            with self.assertRaisesRegex(ValueError, "decompile failed"):
                self.build()
        self.assert_not_published()
        self.assertEqual((self.root / "previous-private-review/previous.txt").read_text(),
                         "keep this")

    def test_symlink_and_unrecognized_private_files_block(self):
        linked = self.root / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            bundle.build(self.binary, self.srs, self.config, self.snapshot,
                         "br-lan", linked / "private-review")
        self.assert_not_published()
        with patch.object(bundle.prepare.__globals__["subprocess"], "run",
                          side_effect=self.fake_decompile):
            self.build()
            (self.output / "unexpected").write_text("unreviewed")
            with self.assertRaisesRegex(ValueError, "unexpected private bundle"):
                bundle.audit(self.output, self.binary, reproduce=False)
            (self.output / "unexpected").unlink()
            original = self.output / bundle.CONFIG
            original.unlink()
            original.symlink_to(self.config)
            with self.assertRaisesRegex(ValueError, "restricted"):
                bundle.audit(self.output, self.binary, reproduce=False)

    def test_ipv4_literal_only_bundle_has_no_snapshot_and_still_matches(self):
        self.config.write_text(json.dumps({"outbounds": [
            {"type": "hysteria2", "server": "8.8.8.8", "server_port": 443}]}))
        with patch.object(bundle.prepare.__globals__["subprocess"], "run",
                          side_effect=self.fake_decompile):
            report = self.build(snapshot=False)
            self.assertEqual(report["source_file_count"], 2)
            self.assertFalse((self.output / bundle.SNAPSHOT).exists())
            self.assertEqual(bundle.audit(self.output, self.binary)["dns_valid_until"], None)

    def test_snapshot_expires_during_reproduction_and_does_not_publish(self):
        self.snapshot.write_text(json.dumps({
            "config_sha256": hashlib.sha256(self.config.read_bytes()).hexdigest(),
            "captured_at": self.now,
            "records": {"edge.example": {
                "ipv4": ["1.1.1.1"], "expires_at": self.now + 5}}}))
        # The second decompile happens in the independent reproduction pass.
        # Advance simulated time there, regardless of unrelated clock calls.
        with patch.object(bundle.prepare.__globals__["subprocess"], "run",
                          side_effect=self.fake_decompile), \
                patch.object(bundle.time, "time",
                             side_effect=lambda: self.now + 6 if self.calls >= 2 else self.now):
            with self.assertRaisesRegex(ValueError, "expired"):
                self.build()
        self.assert_not_published()

    def test_snapshot_changed_during_reproduction_does_not_publish(self):
        self.snapshot.write_text(json.dumps({
            "config_sha256": hashlib.sha256(self.config.read_bytes()).hexdigest(),
            "captured_at": self.now,
            "records": {"edge.example": {
                "ipv4": ["1.1.1.1"], "expires_at": self.now + 5}}}))
        def expire_on_second_decompile(command, **kwargs):
            self.fake_decompile(command, **kwargs)
            if self.calls == 2:
                self.snapshot.write_text(self.snapshot.read_text() + " ")
        with patch.object(bundle.prepare.__globals__["subprocess"], "run",
                          side_effect=expire_on_second_decompile):
            with self.assertRaisesRegex(ValueError, "input changed"):
                self.build()
        self.assert_not_published()


if __name__ == "__main__":
    unittest.main()
