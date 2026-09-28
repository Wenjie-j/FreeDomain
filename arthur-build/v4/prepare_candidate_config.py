#!/usr/bin/env python3
"""Merge a limited V4 config fragment into an offline V3 config copy."""
import argparse
import re
from pathlib import Path

SETTING = re.compile(r"^(?:CONFIG_([A-Za-z0-9_-]+)=|# CONFIG_([A-Za-z0-9_-]+) is not set$)")
NEEDS = ("TARGET_qualcommax_ipq60xx_DEVICE_jdcloud_re-ss-01",
         "PACKAGE_kmod-qca-nss-drv", "PACKAGE_kmod-qca-nss-ecm")


def merge(original: str, fragment: str) -> str:
    if not all(f"CONFIG_{key}=y" in original.splitlines() for key in NEEDS):
        raise ValueError("source config is not the expected Arthur V3/NSS target")
    replacements = {}
    for line in fragment.splitlines():
        m = SETTING.match(line)
        if m:
            key = m.group(1) or m.group(2)
            if key in replacements:
                raise ValueError("duplicate fragment setting")
            replacements[key] = line
    lines = []
    for line in original.splitlines():
        m = SETTING.match(line)
        if not m or (m.group(1) or m.group(2)) not in replacements:
            lines.append(line)
    lines.extend(replacements.values())
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--v3-config", type=Path, required=True)
    ap.add_argument("--fragment", type=Path,
                    default=Path(__file__).with_name("candidate.config.fragment"))
    ap.add_argument("--output", type=Path, required=True,
                    help="Offline build-tree config copy; never a router path")
    args = ap.parse_args()
    args.output.write_text(merge(args.v3_config.read_text(encoding="utf-8"),
                                 args.fragment.read_text(encoding="utf-8")),
                           encoding="utf-8")


if __name__ == "__main__":
    main()
