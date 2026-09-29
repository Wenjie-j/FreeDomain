import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("prepare_current_ui", HERE / "prepare_current_singbox_ui.py")
import sys
sys.path.insert(0, str(HERE))
porter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(porter)


class ControllerPort(unittest.TestCase):
    def test_all_mutations_become_post_only_and_list_stays_get(self):
        routes = ''.join(
            'entry({"admin","services","singbox","api","%s"}, call("api_%s")).leaf=true\n'
            % (action, action) for action in porter.MUTATIONS
        )
        routes += 'entry({"admin","services","singbox","api","list"}, call("api_list")).leaf=true\n'
        routes += 'local function require_post()\n    if not csrf() then\n'
        hardened = porter.harden_controller(routes)
        for action in porter.MUTATIONS:
            self.assertIn('post("api_%s")' % action, hardened)
            self.assertNotIn('call("api_%s")' % action, hardened)
        self.assertIn('call("api_list")', hardened)
        self.assertIn('getenv("REQUEST_METHOD") ~= "POST"', hardened)
        with self.assertRaises(ValueError):
            porter.harden_controller(hardened)


class RuntimePort(unittest.TestCase):
    def test_manager_restores_service_before_claiming_recovery(self):
        old = '''    sys.call("uci set singbox.main.proxy_node="..shquote(db.active))
    sys.call("uci commit singbox")
    if restart then
        local ok,re=restart_services()
        if not ok then
            sys.call("cp -f "..shquote(CFG..".manager-backup").." "..shquote(CFG))
            restart_services()
            return nil,re.."；已自动恢复上一个配置"
        end
    end
    return true'''
        new = porter.port_manager(old)
        self.assertLess(new.index("local ok,re=restart_services()"),
                        new.index("uci set singbox.main.proxy_node"))
        self.assertIn("旧配置恢复失败，需人工检查", new)
        self.assertIn("旧配置已恢复，但服务恢复失败", new)
        self.assertIn("旧配置和服务已恢复", new)
        with self.assertRaises(ValueError):
            porter.port_manager(new)

    def test_status_rejects_old_contract_and_checks_the_runtime_sources(self):
        old = '''    return sys.call("iptables -t nat -S SINGBOX_TCP >/dev/null 2>&1")==0 and "已启用" or "未启用"
    local x=sys.exec("uci -q get dhcp.@dnsmasq[0].server 2>/dev/null")
    return x:find("127.0.0.1#1053",1,true) and "已启用 → 127.0.0.1:1053" or "未启用"'''
        new = porter.port_status(old)
        self.assertNotIn("iptables", new)
        self.assertNotIn("uci -q get dhcp", new)
        self.assertIn("nft list chain inet fw4 arthur_singbox_udp", new)
        self.assertIn("/tmp/dnsmasq.d/99-arthur-singbox.conf", new)
        self.assertIn("/var/etc/dnsmasq.conf.*", new)
        self.assertIn("待查询验证", new)
        with self.assertRaises(ValueError):
            porter.port_status(new)

    def test_setup_refuses_to_proceed_without_generated_dns_include(self):
        old = '''#!/bin/sh
dns_on() { :; }
start() {
    wait_core || {
        return 1
    }

    /usr/bin/sing-box-firewall start || { :; }
}
stop() { /usr/bin/sing-box-firewall stop; }
'''
        new = porter.port_setup(old)
        self.assertNotIn("/usr/bin/sing-box-firewall start", new)
        self.assertLess(new.index("dns_include_ready ||"),
                        new.index("/usr/bin/sing-box-firewall4 start"))
        self.assertEqual(subprocess.run(["sh", "-n"], input=new, text=True,
                                        capture_output=True).returncode, 0)
        with tempfile.TemporaryDirectory() as directory:
            conf = Path(directory) / "dnsmasq.conf.test"
            gate = new[new.index("dns_include_ready() {"):new.index("dns_on() {")]
            gate = gate.replace("/var/etc/dnsmasq.conf.*", str(conf))
            def ready():
                return subprocess.run(["sh", "-c", gate + "\ndns_include_ready"],
                                      capture_output=True).returncode == 0
            self.assertFalse(ready())
            conf.write_text("server=127.0.0.1#1053\n")
            self.assertFalse(ready())
            conf.write_text("conf-dir=/tmp/dnsmasq.d\n")
            self.assertTrue(ready())
            conf.write_text("conf-file=/tmp/dnsmasq.d/99-arthur-singbox.conf\n")
            self.assertTrue(ready())
        with self.assertRaises(ValueError):
            porter.port_setup(new)


if __name__ == "__main__":
    unittest.main()
