#!/usr/bin/env python3
"""Generate a deterministic OpenWrt feeds.conf from reviewed candidate revisions."""
import argparse
import json
import re
from pathlib import Path

EXPECTED = ("packages", "luci", "routing", "telephony", "nss_packages",
            "sqm_scripts_nss", "video", "argon")
SHA = re.compile(r"[0-9a-f]{40}\Z")
URL = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git\Z")


def generate(lock: dict) -> str:
    feeds = lock["feeds"]
    if tuple(f["name"] for f in feeds) != EXPECTED:
        raise ValueError("feed list/order differs from the reviewed source set")
    if not SHA.fullmatch(lock["base"]["revision"]):
        raise ValueError("base source revision is not a full commit hash")
    lines = ["# Candidate V4 source revisions; component and runtime gates still required."]
    for feed in feeds:
        if not SHA.fullmatch(feed["revision"]) or not URL.fullmatch(feed["repository"]):
            raise ValueError("invalid feed revision or repository URL")
        lines.append(f"src-git {feed['name']} {feed['repository']}^{feed['revision']}")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lock", type=Path, default=Path(__file__).with_name("feeds.lock.json"))
    ap.add_argument("--output", type=Path, required=True,
                    help="Explicit path in an isolated build tree; never a router path")
    args = ap.parse_args()
    args.output.write_text(generate(json.loads(args.lock.read_text(encoding="utf-8"))),
                           encoding="utf-8")


if __name__ == "__main__":
    main()
