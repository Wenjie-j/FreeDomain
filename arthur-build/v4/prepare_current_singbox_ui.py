#!/usr/bin/env python3
"""Stage a private LuCI source candidate, with unsafe runtime hooks excluded.

The source archive stays private. The output is an offline working directory,
not an OpenWrt package or a flashable integration.
"""

import argparse
import json
import os
import re
import tarfile
from pathlib import Path

from audit_current_singbox_ui import MUTATIONS, audit


STAGED = (
    "usr/lib/lua/luci/controller/singbox.lua",
    "usr/lib/lua/luci/view/singbox/nodes.htm",
    "usr/lib/lua/luci/model/cbi/singbox_status.lua",
    "usr/lib/lua/singbox/manager.lua",
    "etc/init.d/sing-box",
)


def harden_controller(source):
    for action in MUTATIONS:
        route = re.compile(
            r'(entry\(\{"admin","services","singbox","api","'
            + action + r'"\}, )call\("api_' + action + r'"\)(\))'
        )
        source, count = route.subn(r'\1post("api_' + action + r'")\2', source)
        if count != 1:
            raise ValueError("mutation route contract changed: " + action)
    old = '''local function require_post()
    if not csrf() then'''
    new = '''local function require_post()
    if http().getenv("REQUEST_METHOD") ~= "POST" then
        http().status(405, "Method Not Allowed")
        http().header("Allow", "POST")
        reply(false, nil, "仅允许 POST 请求")
        return false
    end
    if not csrf() then'''
    if source.count(old) != 1:
        raise ValueError("CSRF contract changed")
    return source.replace(old, new, 1)


def port_status(source):
    old_firewall = '''    return sys.call("iptables -t nat -S SINGBOX_TCP >/dev/null 2>&1")==0 and "已启用" or "未启用"'''
    new_firewall = '''    local udp=sys.call("nft list chain inet fw4 arthur_singbox_udp >/dev/null 2>&1")==0
    local tcp=sys.call("nft list chain inet fw4 arthur_singbox_tcp_dns >/dev/null 2>&1")==0
    return udp and tcp and "规则已加载（待流量验证）" or "未启用"'''
    old_dns = '''    local x=sys.exec("uci -q get dhcp.@dnsmasq[0].server 2>/dev/null")
    return x:find("127.0.0.1#1053",1,true) and "已启用 → 127.0.0.1:1053" or "未启用"'''
    new_dns = '''    local runtime=fs.readfile("/tmp/dnsmasq.d/99-arthur-singbox.conf") or ""
    local has_server=runtime:find("server=127.0.0.1#1053",1,true)~=nil
    local owner=(fs.readfile("/tmp/dnsmasq.d/.99-arthur-singbox.owner") or ""):match("^([0-9a-f]+)%s*$")
    local digest=(sys.exec("sha256sum /tmp/dnsmasq.d/99-arthur-singbox.conf 2>/dev/null") or ""):match("^([0-9a-f]+)")
    local owned=owner~=nil and owner==digest
    local confdir=sys.call("grep -Fxq 'conf-dir=/tmp/dnsmasq.d' /var/etc/dnsmasq.conf.* >/dev/null 2>&1")==0
    local conffile=sys.call("grep -Fxq 'conf-file=/tmp/dnsmasq.d/99-arthur-singbox.conf' /var/etc/dnsmasq.conf.* >/dev/null 2>&1")==0
    return owned and has_server and (confdir or conffile) and "配置文件已包含（待查询验证）" or "未生效"'''
    if source.count(old_firewall) != 1 or source.count(old_dns) != 1:
        raise ValueError("Sing-box status backend contract changed")
    return source.replace(old_firewall, new_firewall, 1).replace(old_dns, new_dns, 1)


def port_setup(source):
    old = "/usr/bin/sing-box-firewall"
    if source.count(old) < 2 or "dns_on() {" not in source:
        raise ValueError("Sing-box setup service contract changed")
    gate = '''dns_include_ready() {
    for conf in /var/etc/dnsmasq.conf.*; do
        [ -f "$conf" ] || continue
        grep -Fxq 'conf-dir=/tmp/dnsmasq.d' "$conf" && return 0
        grep -Fxq 'conf-file=/tmp/dnsmasq.d/99-arthur-singbox.conf' "$conf" && return 0
    done
    return 1
}

'''
    start = '''start() {
    wait_core || {'''
    if source.count(start) != 1:
        raise ValueError("Sing-box setup start contract changed")
    source = source.replace("dns_on() {", gate + "dns_on() {", 1)
    source = source.replace(old, "/usr/bin/sing-box-firewall4")
    old_start = '''        return 1
    }

    /usr/bin/sing-box-firewall4 start || {'''
    new_start = '''        return 1
    }
    dns_include_ready || {
        logger -t sing-box-setup "generated dnsmasq config does not include runtime DNS"
        return 1
    }

    /usr/bin/sing-box-firewall4 start || {'''
    if source.count(old_start) != 1:
        raise ValueError("Sing-box setup firewall start contract changed")
    source = source.replace(old_start, new_start, 1)
    old_dns = '''dns_on() {
    mkdir -p "$RUNTIME_DIR" || return 1
    tmp="$RUNTIME_CONF.tmp.$$"

    cat >"$tmp" <<'EOF'
# Arthur Sing-box runtime DNS
no-resolv
server=127.0.0.1#1053
EOF

    chmod 0644 "$tmp"
    mv -f "$tmp" "$RUNTIME_CONF" || return 1

    /etc/init.d/dnsmasq restart || return 1
    wait_dnsmasq || return 1
    return 0
}

dns_off() {
    rm -f "$RUNTIME_CONF"
    /etc/init.d/dnsmasq restart || return 1
    wait_dnsmasq || return 1
    return 0
}'''
    new_dns = '''dns_owned() {
    [ -f "$RUNTIME_CONF" ] && [ ! -L "$RUNTIME_CONF" ] || return 1
    [ -f "$RUNTIME_OWNER" ] && [ ! -L "$RUNTIME_OWNER" ] || return 1
    digest=$(sha256sum "$RUNTIME_CONF" 2>/dev/null) || return 1
    digest=${digest%% *}
    IFS= read -r recorded < "$RUNTIME_OWNER" || return 1
    [ "$digest" = "$recorded" ]
}

dns_on() {
    mkdir -p "$RUNTIME_DIR" || return 1
    if [ -e "$RUNTIME_CONF" ] || [ -L "$RUNTIME_CONF" ] ||
       [ -e "$RUNTIME_OWNER" ] || [ -L "$RUNTIME_OWNER" ]; then
        dns_owned || return 1
    else
        tmp="$RUNTIME_CONF.tmp.$$"
        owner_tmp="$RUNTIME_OWNER.tmp.$$"
        cat >"$tmp" <<'EOF'
# Arthur Sing-box runtime DNS
no-resolv
server=127.0.0.1#1053
EOF
        chmod 0644 "$tmp" || { rm -f "$tmp"; return 1; }
        mv -f "$tmp" "$RUNTIME_CONF" || { rm -f "$tmp"; return 1; }
        digest=$(sha256sum "$RUNTIME_CONF" 2>/dev/null) || {
            rm -f "$RUNTIME_CONF"; return 1;
        }
        printf '%s\\n' "${digest%% *}" > "$owner_tmp" || {
            rm -f "$RUNTIME_CONF" "$owner_tmp"; return 1;
        }
        chmod 0600 "$owner_tmp" || {
            rm -f "$RUNTIME_CONF" "$owner_tmp"; return 1;
        }
        mv -f "$owner_tmp" "$RUNTIME_OWNER" || {
            rm -f "$RUNTIME_CONF" "$owner_tmp"; return 1;
        }
    fi
    /etc/init.d/dnsmasq restart || return 1
    wait_dnsmasq || return 1
}

dns_off() {
    if [ ! -e "$RUNTIME_CONF" ] && [ ! -L "$RUNTIME_CONF" ] &&
       [ ! -e "$RUNTIME_OWNER" ] && [ ! -L "$RUNTIME_OWNER" ]; then
        return 0
    fi
    dns_owned || return 1
    rm -f "$RUNTIME_CONF" "$RUNTIME_OWNER" || return 1
    /etc/init.d/dnsmasq restart || return 1
    wait_dnsmasq || return 1
}'''
    old_failure = '''    dns_on || {
        rm -f "$RUNTIME_CONF"
        /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true'''
    new_failure = '''    dns_on || {
        dns_off >/dev/null 2>&1 || true'''
    old_stop = '''stop() {
    dns_off
    /usr/bin/sing-box-firewall4 stop
    logger -t sing-box-setup "transparent proxy and runtime DNS disabled"
}'''
    new_stop = '''stop() {
    dns_off
    dns_rc=$?
    /usr/bin/sing-box-firewall4 stop
    fw_rc=$?
    if [ "$dns_rc" -ne 0 ] || [ "$fw_rc" -ne 0 ]; then
        logger -t sing-box-setup "stop incomplete; inspect DNS ownership and firewall state"
        return 1
    fi
    logger -t sing-box-setup "transparent proxy and runtime DNS disabled"
}'''
    owner_line = 'RUNTIME_CONF="$RUNTIME_DIR/99-arthur-singbox.conf"\n'
    if (source.count(owner_line) != 1 or source.count(old_dns) != 1
            or source.count(old_failure) != 1 or source.count(old_stop) != 1):
        raise ValueError("runtime DNS ownership contract changed")
    return (source.replace(owner_line, owner_line + 'RUNTIME_OWNER="$RUNTIME_DIR/.99-arthur-singbox.owner"\n', 1)
            .replace(old_dns, new_dns, 1)
            .replace(old_failure, new_failure, 1)
            .replace(old_stop, new_stop, 1))


def port_manager(source):
    """Keep UCI state behind the service check and report rollback failures."""
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
    new = '''    if restart then
        local ok,re=restart_services()
        if not ok then
            local restored=sys.call("cp -f "..shquote(CFG..".manager-backup").." "..shquote(CFG))
            if restored~=0 then
                return nil,re.."；旧配置恢复失败，需人工检查"
            end
            local running,restore_error=restart_services()
            if not running then
                return nil,re.."；旧配置已恢复，但服务恢复失败："..tostring(restore_error)
            end
            return nil,re.."；旧配置和服务已恢复"
        end
    end
    sys.call("uci set singbox.main.proxy_node="..shquote(db.active))
    sys.call("uci commit singbox")
    return true'''
    if source.count(old) != 1:
        raise ValueError("manager restart/rollback contract changed")
    return source.replace(old, new, 1)


def stage(archive_path, destination, services_archive=None):
    report = audit(archive_path, services_archive)
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("output directory must be empty")
    with tarfile.open(archive_path, "r:gz") as archive:
        names = {entry.name.removeprefix("./"): entry for entry in archive if entry.isfile()}
        missing = set(STAGED) - set(names)
        if missing:
            raise ValueError("essential LuCI source missing: " + ", ".join(sorted(missing)))
        staged = {}
        for name in STAGED:
            staged[name] = archive.extractfile(names[name]).read()
    if services_archive is not None:
        with tarfile.open(services_archive, "r:gz") as archive:
            staged["etc/init.d/sing-box-setup"] = archive.extractfile(
                "etc/init.d/sing-box-setup"
            ).read()

    controller_name = STAGED[0]
    staged[controller_name] = harden_controller(staged[controller_name].decode()).encode()
    status_name = STAGED[2]
    staged[status_name] = port_status(staged[status_name].decode()).encode()
    manager_name = STAGED[3]
    staged[manager_name] = port_manager(staged[manager_name].decode()).encode()
    if services_archive is not None:
        setup_name = "etc/init.d/sing-box-setup"
        staged[setup_name] = port_setup(staged[setup_name].decode()).encode()
    destination.mkdir(parents=True, exist_ok=True)
    os.chmod(destination, 0o700)
    for name, content in staged.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(0o600)
    (destination / "OFFLINE-ONLY.json").write_text(
        json.dumps({
            "archive_sha256": report["archive_sha256"],
            "services_archive_sha256": report["services_archive_sha256"],
            "staged_paths": list(staged),
            "excluded_runtime_paths": [
                "usr/bin/sing-box-firewall",
                "usr/bin/sing-box-update-rules",
                "etc/init.d/anyreality",
            ],
            "source_archive_blockers": report["blockers"],
            "candidate_controller_method_hardened": True,
            "candidate_status_ported": True,
            "candidate_setup_ported": services_archive is not None,
            "candidate_setup_dns_owner_hardened": services_archive is not None,
            "candidate_manager_rollback_hardened": True,
            "warning": "Private offline source candidate; never install as firmware overlay.",
        }, indent=2) + "\n"
    )
    return report, len(staged)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--services-archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result, count = stage(args.archive, args.output, args.services_archive)
    print(json.dumps({
        "staged_file_count": count,
        "archive_sha256": result["archive_sha256"],
        "services_archive_sha256": result["services_archive_sha256"],
        "source_archive_blockers": result["blockers"],
        "candidate_controller_method_hardened": True,
        "candidate_status_ported": True,
        "candidate_setup_ported": args.services_archive is not None,
        "candidate_setup_dns_owner_hardened": args.services_archive is not None,
        "candidate_manager_rollback_hardened": True,
        "offline_only": True,
    }, indent=2))


if __name__ == "__main__":
    main()
