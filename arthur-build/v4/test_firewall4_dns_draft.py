import importlib.util
import json
import pathlib
import unittest


HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


firewall = load("render_firewall4_draft")
dns = load("check_dnsmasq_include")


class Firewall4DraftTest(unittest.TestCase):
    @staticmethod
    def geoip():
        # Enough distinct /32 values to exercise the old 5000-CIDR gate.
        cidrs = [f"11.{n // 65536}.{n // 256 % 256}.{n % 256}/32" for n in range(5000)]
        return json.dumps({"rules": [{"ip_cidr": cidrs}]})

    def test_candidate_keeps_udp_tproxy_tcp_redirect_and_cn_bypass(self):
        output = firewall.render(self.geoip(), "br-lan", "8.8.8.8")
        self.assertIn("tproxy ip to :7895 meta mark set 0x66", output)
        self.assertIn("meta l4proto tcp redirect to :7892", output)
        self.assertIn("ip daddr @arthur_cn4 return", output)
        self.assertEqual(output.count("ip daddr 8.8.8.8 return"), 2)
        self.assertLess(output.index("ip daddr 8.8.8.8 return"),
                        output.index("ip daddr @arthur_cn4 return"))
        self.assertIn('iifname "br-lan" meta nfproto ipv6 reject', output)
        self.assertNotIn("HY2_IP", output)

    def test_rejects_untrusted_interface_and_bad_geoip(self):
        with self.assertRaises(ValueError):
            firewall.render(self.geoip(), 'br-lan"; flush ruleset', "8.8.8.8")
        for address in ("", "127.0.0.1", "192.168.1.1", "8.8.8.8; flush ruleset"):
            with self.assertRaises(ValueError):
                firewall.render(self.geoip(), "br-lan", address)
        with self.assertRaises(ValueError):
            firewall.render(json.dumps({"rules": [{"ip_cidr": ["11.0.0.0/8"]}]}), "br-lan", "8.8.8.8")
        with self.assertRaises(ValueError):
            firewall.render(json.dumps({"rules": [{"ip_cidr": ["garbage"]}]}), "br-lan", "8.8.8.8")


class DnsIncludeTest(unittest.TestCase):
    def test_requires_generated_config_to_include_exact_runtime_file(self):
        self.assertFalse(dns.check("# conf-dir=/tmp/dnsmasq.d\n")["runtime_dns_included"])
        self.assertFalse(dns.check("conf-dir=/etc/dnsmasq.d\n")["runtime_dns_included"])
        self.assertFalse(dns.check("conf-dir=/tmp/dnsmasq.d,*.cfg\n")["runtime_dns_included"])
        self.assertTrue(dns.check("conf-dir=/tmp/dnsmasq.d\n")["runtime_dns_included"])
        self.assertTrue(dns.check("conf-file=/tmp/dnsmasq.d/99-arthur-singbox.conf\n")["runtime_dns_included"])
        self.assertFalse(dns.check("conf-dir=/tmp/dnsmasq.d\n")["active_process_verified"])


if __name__ == "__main__":
    unittest.main()
