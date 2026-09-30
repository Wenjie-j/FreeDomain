import json
import pathlib
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import refresh_proxy_dns_snapshot as refresh


def answer(domain="proxy.example", records=None, status="NOERROR", flags="qr rd ra"):
    records = records if records is not None else [f"{domain}. 60 IN A 1.1.1.1"]
    return "\n".join([
        f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 1234",
        f";; flags: {flags}; QUERY: 1, ANSWER: {len(records)}, AUTHORITY: 0, ADDITIONAL: 0",
        ";; QUESTION SECTION:", f";{domain}. IN A", ";; ANSWER SECTION:", *records])


class DnsAnswerTests(unittest.TestCase):
    def test_cname_and_all_addresses_use_lowest_ttl(self):
        raw = answer(records=["proxy.example. 30 IN CNAME edge.example.",
                              "edge.example. 90 IN A 9.9.9.9",
                              "edge.example. 20 IN A 1.1.1.1"])
        ips, ttl = refresh.parse_answer(raw, "proxy.example")
        self.assertEqual(ips, ["1.1.1.1", "9.9.9.9"])
        self.assertEqual(ttl, 20)
        self.assertEqual(refresh.parse_answer(
            answer(records=["proxy.example. 7200 IN A 1.1.1.1"]), "proxy.example")[1], 900)

    def test_failed_empty_wrong_question_and_truncated_answers_block(self):
        for raw in (answer(status="NXDOMAIN"), answer(status="SERVFAIL"),
                    answer(records=[]), answer(domain="other.example"),
                    answer(flags="qr tc rd"), answer(flags="rd ra"),
                    answer().replace("ANSWER: 1", "ANSWER: 2"),
                    answer() + "\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 99"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    refresh.parse_answer(raw, "proxy.example")

    def test_cname_loop_ambiguity_missing_address_and_unrelated_records_block(self):
        variants = [
            ["proxy.example. 60 IN CNAME proxy.example."],
            ["proxy.example. 60 IN CNAME absent.example."],
            ["proxy.example. 60 IN CNAME edge.example.", "edge.example. 60 IN CNAME proxy.example."],
            ["proxy.example. 60 IN CNAME edge.example.", "proxy.example. 60 IN A 1.1.1.1"],
            ["proxy.example. 60 IN CNAME edge.example.", "proxy.example. 60 IN CNAME other.example."],
            ["proxy.example. 60 IN A 1.1.1.1", "other.example. 60 IN A 9.9.9.9"],
        ]
        for records in variants:
            with self.subTest(records=records):
                with self.assertRaises(ValueError):
                    refresh.parse_answer(answer(records=records), "proxy.example")

    def test_bad_ttl_nonpublic_ipv6_and_oversized_answers_block(self):
        for line in ("proxy.example. 0 IN A 1.1.1.1", "proxy.example. -1 IN A 1.1.1.1",
                     "proxy.example. 2147483648 IN A 1.1.1.1", "proxy.example. 60 IN A 10.0.0.1",
                     "proxy.example. 60 IN A 100.64.0.1", "proxy.example. 60 IN A ::1",
                     "proxy.example. 60 IN AAAA 2001:4860:4860::8888"):
            with self.assertRaises(ValueError):
                refresh.parse_answer(answer(records=[line]), "proxy.example")
        with self.assertRaises(ValueError):
            refresh.parse_answer(" " * 65537, "proxy.example")


class SnapshotRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.config = self.root / "private-config.json"
        self.config.write_text(json.dumps({"outbounds": [
            {"type": "vless", "server": "proxy.example", "server_port": 443,
             "password": "secret-never-report"}]}))
        self.output = self.root / "snapshot.json"
        self.old = json.dumps({"config_sha256": "a" * 64, "captured_at": 1,
                               "records": {}}).encode()
        self.output.write_bytes(self.old)

    def runner(self, command, **kwargs):
        self.assertIsInstance(command, list)
        self.assertNotIn("shell", kwargs)
        self.assertIn("-r", command)
        self.assertIn("+noedns", command)
        self.assertLessEqual(kwargs["timeout"], 5)
        self.assertEqual(kwargs["env"]["LC_ALL"], "C")
        domain = command[command.index("-q") + 1].removesuffix(".")
        return SimpleNamespace(stdout=answer(domain), returncode=0)

    def run_refresh(self, runner=None, clock=None):
        return refresh.refresh(self.config, "8.8.8.8", self.output,
                               runner=runner or self.runner,
                               clock=clock or (lambda: 1000))

    def assert_old_and_clean(self):
        self.assertEqual(self.output.read_bytes(), self.old)
        self.assertFalse((self.root / ".snapshot.json.refresh-lock").exists())
        self.assertFalse(list(self.root.glob(".dns-snapshot-*")))

    def test_success_commits_private_config_bound_snapshot_with_no_public_secrets(self):
        report = self.run_refresh()
        snapshot = json.loads(self.output.read_bytes())
        self.assertEqual(snapshot["records"]["proxy.example"]["expires_at"], 1060)
        ips, _ = refresh.collect(self.config.read_bytes(), self.output.read_bytes(), now=1001)
        self.assertEqual(ips, ["1.1.1.1"])
        self.assertTrue(report["snapshot_replaced_atomically"])
        self.assertTrue(report["offline_dns_query_implemented"])
        self.assertFalse(report["scheduled_refresh_implemented"])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        for value in ("secret-never-report", "proxy.example", "8.8.8.8", "1.1.1.1"):
            self.assertNotIn(value, json.dumps(report))
        self.assertFalse((self.root / ".snapshot.json.refresh-lock").exists())

    def test_query_failure_and_partial_resolution_preserve_previous_file(self):
        data = json.loads(self.config.read_text())
        data["outbounds"].append({"type": "trojan", "server": "second.example", "server_port": 443})
        self.config.write_text(json.dumps(data))
        calls = []

        def fails_second(command, **kwargs):
            calls.append(command)
            if len(calls) == 2:
                raise OSError("synthetic resolver unavailable")
            return self.runner(command, **kwargs)

        with self.assertRaisesRegex(ValueError, "query failed"):
            self.run_refresh(runner=fails_second)
        self.assertEqual(len(calls), 2)
        self.assert_old_and_clean()

    def test_changed_config_rejects_new_snapshot(self):
        def changes_config(command, **kwargs):
            result = self.runner(command, **kwargs)
            self.config.write_bytes(self.config.read_bytes() + b" ")
            return result
        with self.assertRaisesRegex(ValueError, "config changed"):
            self.run_refresh(runner=changes_config)
        self.assert_old_and_clean()

    def test_expiry_at_generation_or_commit_preserves_previous_file(self):
        for timeline in ([1000, 1000, 1060], [1000, 1000, 1000, 1060]):
            ticks = iter(timeline)
            with self.assertRaises(ValueError):
                self.run_refresh(clock=lambda: next(ticks))
            self.assert_old_and_clean()

    def test_clock_reversal_and_query_budget_preserve_previous_file(self):
        for timeline in ([1000, 999], [1000, 1045], [1000, 1000, 1045]):
            ticks = iter(timeline)
            with self.assertRaises(ValueError):
                self.run_refresh(clock=lambda: next(ticks))
            self.assert_old_and_clean()

    def test_failed_atomic_replace_preserves_old_and_removes_temporary_files(self):
        with patch.object(refresh.os, "replace", side_effect=OSError("synthetic disk error")):
            with self.assertRaises(OSError):
                self.run_refresh()
        self.assert_old_and_clean()

    def test_foreign_snapshot_change_is_not_overwritten(self):
        changed = json.dumps({"config_sha256": "b" * 64, "captured_at": 5,
                              "records": {}}).encode()

        def changes_output(command, **kwargs):
            self.output.write_bytes(changed)
            return self.runner(command, **kwargs)
        with self.assertRaisesRegex(ValueError, "snapshot changed"):
            self.run_refresh(runner=changes_output)
        self.assertEqual(self.output.read_bytes(), changed)
        self.assertFalse(list(self.root.glob(".dns-snapshot-*")))

    def test_existing_lock_is_not_removed(self):
        lock = self.root / ".snapshot.json.refresh-lock"
        lock.mkdir()
        with self.assertRaisesRegex(ValueError, "already locked"):
            self.run_refresh()
        self.assertTrue(lock.is_dir())
        self.assertEqual(self.output.read_bytes(), self.old)

    def test_symlinked_paths_and_foreign_output_files_block(self):
        self.output.unlink()
        self.output.symlink_to(self.config)
        with self.assertRaisesRegex(ValueError, "symlinked"):
            self.run_refresh()
        self.output.unlink()
        self.output.write_bytes(b"do not overwrite")
        with self.assertRaises(ValueError):
            self.run_refresh()
        self.assertEqual(self.output.read_bytes(), b"do not overwrite")
        self.output.write_bytes(self.old)
        linked = self.root / "linked"
        linked.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            refresh.refresh(self.config, "8.8.8.8", linked / self.output.name,
                            runner=self.runner, clock=lambda: 1000)

    @unittest.skipUnless(shutil.which("dig"), "dig is installed in cloud checks")
    def test_real_dig_uses_loopback_dns_fixture_with_cname_and_multiple_a(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(5)
        port = server.getsockname()[1]
        failures = []

        def name(value):
            return b"".join(bytes([len(label)]) + label.encode() for label in value.split(".")) + b"\0"

        def respond():
            try:
                query, peer = server.recvfrom(4096)
                offset = 12
                while query[offset]:
                    offset += query[offset] + 1
                question = query[12:offset + 5]
                alias = name("edge.example")
                cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 40, len(alias)) + alias
                first = alias + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("1.1.1.1")
                second = alias + struct.pack("!HHIH", 1, 1, 50, 4) + socket.inet_aton("9.9.9.9")
                packet = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 3, 0, 0)
                server.sendto(packet + question + cname + first + second, peer)
            except Exception as exc:
                failures.append(type(exc).__name__)

        thread = threading.Thread(target=respond, daemon=True)
        thread.start()

        def loopback_runner(command, **kwargs):
            local = ["@127.0.0.1" if arg == "@8.8.8.8" else arg for arg in command]
            local[1:1] = ["-p", str(port)]
            return subprocess.run(local, **kwargs)
        try:
            report = self.run_refresh(runner=loopback_runner)
            records = json.loads(self.output.read_bytes())["records"]
            self.assertEqual(records["proxy.example"],
                             {"ipv4": ["1.1.1.1", "9.9.9.9"], "expires_at": 1040})
            self.assertEqual(report["query_count"], 1)
        finally:
            thread.join(timeout=5)
            server.close()
        self.assertFalse(failures)


if __name__ == "__main__":
    unittest.main()
