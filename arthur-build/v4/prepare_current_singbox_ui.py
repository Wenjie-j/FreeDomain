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
        "offline_only": True,
    }, indent=2))


if __name__ == "__main__":
    main()
