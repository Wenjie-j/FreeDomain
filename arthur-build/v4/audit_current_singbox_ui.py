#!/usr/bin/env python3
"""Audit a private, source-only Sing-box export without disclosing its contents.

This tool never extracts the archive, touches a router or marks an image ready.
Its JSON output contains fixed file names, feature names and hashes only.
"""

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path


SOURCE = (
    "usr/lib/lua/luci/controller/singbox.lua",
    "usr/lib/lua/luci/view/singbox/nodes.htm",
    "usr/lib/lua/luci/model/cbi/singbox_status.lua",
    "usr/lib/lua/singbox/manager.lua",
    "etc/init.d/sing-box",
    "etc/init.d/sing-box-setup",
    "etc/init.d/anyreality",
    "usr/bin/sing-box-firewall",
    "usr/bin/sing-box-update-rules",
)
MAX_FILE = 1024 * 1024
MAX_ARCHIVE = 8 * 1024 * 1024
MUTATIONS = (
    "active", "test", "delete", "move", "add_link", "add_raw",
    "add_manual", "update", "sub_add", "sub_update", "sub_rename",
    "sub_delete",
)


def read_source_archive(path):
    path = Path(path)
    if path.stat().st_size > MAX_ARCHIVE:
        raise ValueError("archive exceeds source-only size limit")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    contents = {}
    seen = set()
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name.removeprefix("./")
            if name in seen:
                raise ValueError("duplicate archive member")
            seen.add(name)
            if name.startswith("/") or ".." in Path(name).parts:
                raise ValueError("unsafe archive member path")
            if member.isdir():
                continue
            if not member.isfile() or name not in SOURCE and name not in (
                "usr/lib/lua/luci/model/cbi/singbox.lua",
                "usr/bin/sing-box-node-manager",
                "usr/bin/sing-box-switch-node",
                "usr/bin/sing-box-rollback",
            ):
                raise ValueError("unexpected member type or source-only path")
            if member.size > MAX_FILE:
                raise ValueError("archive member exceeds source-only size limit")
            contents[name] = archive.extractfile(member).read().decode("utf-8", "replace")

    return digest, contents


def audit(path, services_archive=None):
    digest, contents = read_source_archive(path)
    service_digest = None
    if services_archive is not None:
        service_digest, extras = read_source_archive(services_archive)
        if set(contents) & set(extras):
            raise ValueError("duplicate source file across archives")
        if set(extras) != {"etc/init.d/sing-box-setup"}:
            raise ValueError("service archive must contain only sing-box-setup")
        contents.update(extras)
    missing = [name for name in SOURCE if name not in contents]
    controller = contents.get(SOURCE[0], "")
    view = contents.get(SOURCE[1], "")
    manager = contents.get(SOURCE[3], "")
    status = contents.get(SOURCE[2], "")
    firewall = contents.get("usr/bin/sing-box-firewall", "")
    updater = contents.get("usr/bin/sing-box-update-rules", "")
    setup = contents.get("etc/init.d/sing-box-setup", "")

    routes = re.findall(r'entry\(\{\s*"admin","services","singbox","api","([a-z_]+)"\}', controller)
    api_mismatch = sorted(set(MUTATIONS) - set(routes))
    checks = {
        "same_luci_menu": all(x in controller for x in ('"status"', '"nodes"')),
        "node_page_calls_existing_api": 'dispatcher.build_url("admin","services","singbox","api")' in view,
        "node_import_and_test_backend": all(x in manager for x in (
            "function M.test(", "function M.add_subscription(", "function M.set_active(")),
        "service_setup_source_present": "etc/init.d/sing-box-setup" in contents,
        "setup_uses_core_ports": all(":" + port + " " in setup for port in ("7892", "7895", "1053")),
        "setup_calls_current_firewall": "/usr/bin/sing-box-firewall start" in setup,
        "setup_uses_runtime_dns_file": "/tmp/dnsmasq.d" in setup,
        "cn_firewall_list_updated": not (
            "geoip-cn.json" in firewall
            and "geoip-cn.srs" in updater
            and "geoip-cn.json" not in updater
        ),
        "controller_enforces_post_method": bool(re.search(r'REQUEST_METHOD|\bpost\s*\(', controller)),
        "no_legacy_firewall_commands": not any(x in firewall for x in (
            "iptables", "ip6tables", "ipset", "TPROXY")),
        "no_hardcoded_proxy_endpoint": not bool(re.search(r'(?m)^\s*(?:HY2_IP|SERVER_IP)\s*=\s*["\x27]\d', firewall)),
        "status_uses_nonlegacy_firewall_check": "iptables" not in status,
    }
    blockers = [key for key, passed in checks.items() if not passed]
    if api_mismatch:
        blockers.append("missing_mutation_routes")
    return {
        "archive_sha256": digest,
        "services_archive_sha256": service_digest,
        "source_file_count": len(contents),
        "present_expected_paths": [name for name in SOURCE if name in contents],
        "missing_expected_paths": missing,
        "missing_mutation_routes": api_mismatch,
        "checks": checks,
        "port_ready": not blockers and not missing,
        "blockers": blockers,
        "scope": "offline source inspection only; no runtime, image or flash approval",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--services-archive", type=Path, help="separate source-only setup service export")
    parser.add_argument("--output", type=Path, help="write a non-secret JSON report")
    args = parser.parse_args()
    result = audit(args.archive, args.services_archive)
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
