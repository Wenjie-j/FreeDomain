import importlib.util
import hashlib
import io
import json
import pathlib
import tarfile
import tempfile
import unittest

path = pathlib.Path(__file__).with_name("legacy_network_preflight.py")
spec = importlib.util.spec_from_file_location("preflight", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MigrationPreflightTest(unittest.TestCase):
    def test_legacy_topology_blocks_and_never_reveals_values(self):
        old = """network.lan=interface
network.lan.ifname='eth0 eth1 eth2'
network.lan.ipaddr='192.168.100.1'
network.wan=interface
network.wan.ifname='eth3'
network.wan.proto='dhcp'
network.wan6=interface
network.wan6.ifname='ip6_vti0'
network.vpn0=interface
network.vpn0.ifname='tun0'
network.ipsec_server=interface
network.ipsec_server.device='ipsec0'
network.usb=interface
network.usb.ifname='usb0'
network.wan.password='TOP_SECRET'
network.custom_secret=interface
network.custom_secret.device='br-private'
"""
        report = module.parse_uci_show(old, "192.168.100.1")
        self.assertEqual(report["decision"], "BLOCKED_FIRST_MIGRATION")
        self.assertIn("PHYSICAL_ETHERNET_MAPPING_UNVERIFIED", report["blockers"])
        self.assertIn("TUNNEL_SERVICE_MIGRATION_UNVERIFIED", report["blockers"])
        self.assertIn("USB_WAN_MIGRATION_UNVERIFIED", report["blockers"])
        self.assertNotIn("MANAGEMENT_ADDRESS_REQUIRES_EXPLICIT_MIGRATION", report["blockers"])
        self.assertEqual(report["interfaces"]["lan"]["binding_categories"], ["LEGACY_ETHERNET"])
        serialized = json.dumps(report)
        for private in ("TOP_SECRET", "br-private", "custom_secret", "192.168.100.1", "eth3"):
            self.assertNotIn(private, serialized)

    def test_missing_lan_and_management_mismatch_fail_closed(self):
        report = module.parse_uci_show("network.wan=interface\nnetwork.wan.ifname='eth3'",
                                       "192.168.100.1")
        self.assertIn("LAN_OR_WAN_INTERFACE_MISSING", report["blockers"])
        self.assertIn("MANAGEMENT_ADDRESS_REQUIRES_EXPLICIT_MIGRATION", report["blockers"])

    def test_loopback_is_not_a_custom_port(self):
        report = module.parse_uci_show("network.loopback=interface\nnetwork.loopback.ifname='lo'\n"
                                       "network.lan=interface\nnetwork.lan.ifname='eth0'\n"
                                       "network.wan=interface\nnetwork.wan.ifname='eth3'\n")
        self.assertNotIn("UNKNOWN_INTERFACE_BINDING", report["blockers"])
        self.assertNotIn("loopback", report["interfaces"])

    def test_private_collector_archive_is_verified_before_parsing(self):
        secret = b"network.lan=interface\nnetwork.lan.ipaddr='192.168.100.1'\n"
        checksum = hashlib.sha256(secret).hexdigest().encode()
        with tempfile.TemporaryDirectory() as directory:
            archive_path = pathlib.Path(directory) / "network.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name, content in (
                    ("./uci-network.txt", secret),
                    ("./SHA256SUMS.txt", checksum + b"  ./uci-network.txt\n"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
            self.assertEqual(module.read_evidence_archive(archive_path),
                             secret.decode())

            with tarfile.open(archive_path, "w:gz") as archive:
                for name, content in (
                    ("uci-network.txt", secret),
                    ("SHA256SUMS.txt", b"0" * 64 + b"  uci-network.txt\n"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                module.read_evidence_archive(archive_path)


if __name__ == "__main__":
    unittest.main()
