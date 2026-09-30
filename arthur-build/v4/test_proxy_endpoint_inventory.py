import hashlib
import json
import pathlib
import tempfile
import unittest

import proxy_endpoint_inventory as inventory


def encode(value):
    return json.dumps(value).encode()


def proxy(server="1.1.1.1", kind="vless", **extra):
    return {"type": kind, "server": server, "server_port": 443, **extra}


class EndpointInventoryTests(unittest.TestCase):
    def config(self, *outbounds, **extra):
        return encode({"outbounds": list(outbounds), **extra})

    def snapshot(self, config, records, captured=1000):
        return encode({"config_sha256": hashlib.sha256(config).hexdigest(),
                       "captured_at": captured, "records": records})

    def record(self, *addresses, expires=1200):
        return {"ipv4": list(addresses), "expires_at": expires}

    def test_all_servers_deduplicated_even_when_selector_defaults_to_one(self):
        raw = self.config(
            {"type": "direct", "tag": "direct"},
            {"type": "selector", "outbounds": ["first", "second"], "default": "first"},
            proxy("8.8.8.8", tag="first", password="never-report-this"),
            proxy("1.1.1.1", tag="second"), proxy("8.8.8.8", detour="second"))
        ips, report = inventory.collect(raw, now=1100)
        self.assertEqual(ips, ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(report["proxy_server_outbound_count"], 3)
        self.assertIsNone(report["dns_snapshot_valid_until"])
        for secret in ("never-report-this", "first", "1.1.1.1", "8.8.8.8"):
            self.assertNotIn(secret, json.dumps(report))
        self.assertFalse(report["target_firewall_activation_approved"])

    def test_all_domain_answers_combined_with_literal_servers(self):
        raw = self.config(proxy("Proxy.Example."), proxy("backup.example"), proxy("8.8.8.8"))
        snapshot = self.snapshot(raw, {
            "proxy.example": self.record("9.9.9.9", "1.1.1.1", expires=1180),
            "backup.example": self.record("8.8.8.8", expires=1190)})
        ips, report = inventory.collect(raw, snapshot, now=1100)
        self.assertEqual(ips, ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
        self.assertEqual(report["proxy_domain_count"], 2)
        self.assertEqual(report["dns_snapshot_valid_until"], 1180)
        self.assertNotIn("proxy.example", json.dumps(report))
        self.assertFalse(report["automatic_dns_refresh_implemented"])

    def test_missing_snapshot_and_changed_config_block(self):
        raw = self.config(proxy("proxy.example"))
        with self.assertRaisesRegex(ValueError, "snapshot required"):
            inventory.collect(raw, now=1100)
        snapshot = self.snapshot(raw, {"proxy.example": self.record("1.1.1.1")})
        with self.assertRaisesRegex(ValueError, "exact private config"):
            inventory.collect(raw + b" ", snapshot, now=1100)

    def test_stale_future_expired_and_unbounded_records_block(self):
        raw = self.config(proxy("proxy.example"))
        for captured, expiry in ((1901, 2000), (0, 2000), (1000, 1100),
                                 (1000, 1901), (True, 1200), (1000, True)):
            with self.subTest(captured=captured, expiry=expiry):
                snapshot = self.snapshot(raw, {"proxy.example":
                                         self.record("1.1.1.1", expires=expiry)}, captured)
                with self.assertRaises(ValueError):
                    inventory.collect(raw, snapshot, now=1100)

    def test_missing_extra_or_noncanonical_domain_records_block(self):
        raw = self.config(proxy("proxy.example"))
        for records in ({}, {"other.example": self.record("1.1.1.1")},
                        {"Proxy.Example": self.record("1.1.1.1")},
                        {"proxy.example": self.record("1.1.1.1"),
                         "extra.example": self.record("9.9.9.9")}):
            with self.assertRaisesRegex(ValueError, "exactly all proxy domains"):
                inventory.collect(raw, self.snapshot(raw, records), now=1100)

    def test_nonpublic_ipv6_and_empty_dns_answers_block(self):
        raw = self.config(proxy("proxy.example"))
        for answers in ([], ["127.0.0.1"], ["10.0.0.1"], ["100.64.0.1"],
                        ["::1"], ["1.1.1.1", "192.168.1.1"], "1.1.1.1"):
            with self.subTest(answers=answers):
                records = {"proxy.example": {"ipv4": answers, "expires_at": 1200}}
                with self.assertRaises(ValueError):
                    inventory.collect(raw, self.snapshot(raw, records), now=1100)

    def test_invalid_server_hostname_and_nonpublic_literals_block(self):
        for value in ("", " proxy.example", "proxy.example;echo", "localhost",
                      "1.2.3.999", "proxy.example:443", "::1", "10.0.0.1",
                      "100.64.0.1", "8.8.8.8\n", 12):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    inventory.collect(self.config(proxy(value)), now=1100)

    def test_unsupported_transports_invalid_types_and_ports_block(self):
        for outbound in (proxy(kind="wireguard"), proxy(kind="unreviewed"),
                         proxy(kind=[]), proxy(server_port=True),
                         proxy(server_port=0), proxy(server_port=65536),
                         proxy(server_port="443"), {"type": "vless"},
                         {"type": "selector", "server": "1.1.1.1"}, None):
            with self.subTest(outbound=outbound):
                with self.assertRaises(ValueError):
                    inventory.collect(self.config(outbound), now=1100)
        with self.assertRaisesRegex(ValueError, "separate reviewed adapter"):
            inventory.collect(self.config(proxy(), endpoints=[{"type": "wireguard"}]), now=1100)
        with self.assertRaisesRegex(ValueError, "no proxy"):
            inventory.collect(self.config({"type": "direct"}), now=1100)

    def test_duplicate_keys_bad_json_and_nonfinite_values_block(self):
        for raw in (b'{"outbounds":[],"outbounds":[]}', b'{"bad":NaN}',
                    b"\xff", b"[]", b"{}", b"", b"{" * 2000):
            with self.subTest(raw_size=len(raw)):
                with self.assertRaises(ValueError):
                    inventory.collect(raw, now=1100)
        raw = self.config(proxy("proxy.example"))
        snapshot = (b'{"config_sha256":"' + hashlib.sha256(raw).hexdigest().encode()
                    + b'","captured_at":1000,"records":{"proxy.example":{},'
                      b'"proxy.example":{}}}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            inventory.collect(raw, snapshot, now=1100)

    def test_bounds_and_irrelevant_snapshot_block(self):
        with self.assertRaises(ValueError):
            inventory.collect(self.config(*[proxy()] * 1025), now=1100)
        with self.assertRaises(ValueError):
            inventory.collect(b" " * (inventory.MAX_BYTES + 1), now=1100)
        with self.assertRaisesRegex(ValueError, "without any proxy domains"):
            inventory.collect(self.config(proxy()), b"{}", now=1100)
        for now in (True, -1, 1.5):
            with self.assertRaisesRegex(ValueError, "verification time"):
                inventory.collect(self.config(proxy()), now=now)

    def test_private_inputs_reject_symlinked_parent_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            source = base / "private.json"
            source.write_bytes(self.config(proxy()))
            self.assertEqual(inventory.private_bytes(source), source.read_bytes())
            linked = base / "linked"
            linked.symlink_to(base, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "non-symlinked"):
                inventory.private_bytes(linked / source.name)
            source.write_bytes(b" " * (inventory.MAX_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "size"):
                inventory.private_bytes(source)


if __name__ == "__main__":
    unittest.main()
