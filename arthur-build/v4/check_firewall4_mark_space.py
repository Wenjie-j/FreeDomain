#!/usr/bin/env python3
"""Offline mark/table collision screen; never changes firewall or routing state."""

import argparse
import json
import re
from pathlib import Path


MARK = 0x66
MASK = 0xff
TABLE = 166
MARK_RULE = re.compile(r"\bfwmark\s+(0x[0-9a-fA-F]+|[0-9]+)(?:/(0x[0-9a-fA-F]+|[0-9]+))?\b")


def _number(raw):
    return int(raw, 16 if raw.lower().startswith("0x") else 10)


def check(ip_rules, table_routes, fw4_rules, mwan_mask=None):
    blockers = set()
    if not re.search(r"\blookup\s+local\b", ip_rules) or "table inet fw4" not in fw4_rules:
        blockers.add("INPUT_CAPTURE_INCOMPLETE")
    if mwan_mask is None:
        blockers.add("MWAN3_MARK_MASK_NOT_CAPTURED")
    else:
        try:
            mask = _number(mwan_mask)
            if not 0 < mask <= 0xffffffff or mask & MASK:
                blockers.add("MWAN3_MARK_MASK_OVERLAPS_PROXY")
        except (ValueError, AttributeError):
            blockers.add("MWAN3_MARK_MASK_INVALID")
    for line in ip_rules.splitlines():
        if re.search(r"\b(?:lookup|table)\s+166\b", line):
            blockers.add("ROUTING_TABLE_166_ALREADY_REFERENCED")
        if "fwmark" not in line:
            continue
        match = MARK_RULE.search(line)
        if not match:
            blockers.add("UNPARSEABLE_EXISTING_FWMARK_RULE")
            continue
        try:
            mark, mask = _number(match[1]), _number(match[2]) if match[2] else 0xffffffff
            if mark > 0xffffffff or mask > 0xffffffff or (mask & MASK):
                blockers.add("EXISTING_FWMARK_USES_PROXY_BITS")
        except ValueError:
            blockers.add("UNPARSEABLE_EXISTING_FWMARK_RULE")
    if table_routes.strip():
        blockers.add("ROUTING_TABLE_166_NOT_EMPTY")
    if re.search(r"\b(?:chain\s+arthur_singbox_|set\s+arthur_cn4\b)", fw4_rules):
        blockers.add("PROXY_FIREWALL_OBJECT_ALREADY_PRESENT")
    return {
        "classification": "OFFLINE_COLLISION_SCREEN_NOT_ACTIVATION_APPROVAL",
        "planned_mark": "0x66/0xff",
        "planned_table": TABLE,
        "blockers": sorted(blockers),
        "activation_approved": False,
        "target_fw4_check_done": False,
        "target_mwan3_and_nss_traffic_test_done": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip-rule-show", type=Path, required=True)
    parser.add_argument("--table-166-routes", type=Path, required=True)
    parser.add_argument("--fw4-print", type=Path, required=True)
    parser.add_argument("--mwan-mask", help="Copied mwan3.globals.mmx_mask value")
    args = parser.parse_args()
    try:
        paths = (args.ip_rule_show, args.table_166_routes, args.fw4_print)
        if any(path.stat().st_size > 2 * 1024 * 1024 for path in paths):
            raise OSError("capture exceeds size limit")
        inputs = [path.read_text(encoding="utf-8") for path in paths]
        report = check(*inputs, args.mwan_mask)
    except (OSError, UnicodeError):
        report = {"classification": "OFFLINE_COLLISION_SCREEN_NOT_ACTIVATION_APPROVAL",
                  "blockers": ["INPUT_UNREADABLE"], "activation_approved": False}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
