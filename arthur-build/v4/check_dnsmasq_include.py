#!/usr/bin/env python3
"""Check whether a generated dnsmasq config includes the old runtime DNS file.

This is a read-only preflight on a copied generated config, not a router edit.
"""

import argparse
import json
from pathlib import Path


RUNTIME_DIR = "/tmp/dnsmasq.d"
RUNTIME_FILE = RUNTIME_DIR + "/99-arthur-singbox.conf"


def check(config_text):
    entries = []
    for raw in config_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        entries.append((key.strip(), value.strip()))
    included = any(
        key == "conf-dir" and value == RUNTIME_DIR
        or key == "conf-file" and value == RUNTIME_FILE
        for key, value in entries
    )
    return {
        "runtime_dns_included": included,
        "active_process_verified": False,
        "dns_migration_gate": "INCLUDE_FOUND_NEEDS_RUNTIME_TEST" if included else "BLOCKED_NOT_INCLUDED",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-config", type=Path, required=True)
    args = parser.parse_args()
    result = check(args.generated_config.read_text(errors="replace"))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["runtime_dns_included"] else 2)


if __name__ == "__main__":
    main()
