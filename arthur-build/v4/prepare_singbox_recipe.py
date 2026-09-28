#!/usr/bin/env python3
"""Prepare an offline 1.14.1 package recipe after verifying its source archive."""
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path

OLD_VERSION = "PKG_VERSION:=1.14.0"
OLD_HASH = "PKG_HASH:=87baf6852e37941cbe40bdd94bec81c957c88a56751cecd6bbf0e6108bc69398"
REQUIRED_FEATURES = ("SINGBOX_WITH_QUIC", "SINGBOX_WITH_DHCP",
                     "SINGBOX_WITH_WIREGUARD", "SINGBOX_WITH_UTLS",
                     "SINGBOX_WITH_CLASH_API")


def verify_archive(archive: Path, lock: dict) -> None:
    expected = lock["sing_box_source"]
    if expected["tag"] != "v1.14.1" or expected["go_mod_minimum"] != "1.25.5":
        raise ValueError("unreviewed Sing-box source metadata")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != expected["codeload_sha256"]:
        raise ValueError("source archive SHA-256 mismatch")
    with tarfile.open(archive, "r:gz") as tar:
        modules = [m for m in tar.getmembers()
                   if m.isfile() and m.name == "sing-box-1.14.1/go.mod"]
        if len(modules) != 1:
            raise ValueError("source archive lacks a unique go.mod")
        contents = tar.extractfile(modules[0]).read(4096).decode("utf-8")
        if not re.search(r"^module github\.com/sagernet/sing-box$", contents, re.M):
            raise ValueError("unexpected Go module")
        if not re.search(r"^go 1\.25\.5$", contents, re.M):
            raise ValueError("unexpected Go toolchain requirement")


def adapt_makefile(original: str, lock: dict) -> str:
    source = lock["sing_box_source"]
    if source["tag"] != "v1.14.1" or source["revision"] != \
            "1ac1a339cb1223e9c70eae14c44411c75033c02d":
        raise ValueError("Sing-box source is not the pinned upstream v1.14.1")
    if original.count(OLD_VERSION) != 1 or original.count(OLD_HASH) != 1:
        raise ValueError("feed recipe changed; review it before updating")
    if not all(feature in original for feature in REQUIRED_FEATURES):
        raise ValueError("feed recipe lacks required build feature switches")
    return (original.replace(OLD_VERSION, "PKG_VERSION:=1.14.1")
            .replace(OLD_HASH, "PKG_HASH:=" + source["codeload_sha256"]))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lock", type=Path, default=Path(__file__).with_name("feeds.lock.json"))
    ap.add_argument("--source-archive", type=Path, required=True)
    ap.add_argument("--feed-makefile", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True,
                    help="Prepared Makefile for an isolated V4 build tree")
    args = ap.parse_args()
    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    verify_archive(args.source_archive, lock)
    prepared = adapt_makefile(args.feed_makefile.read_text(encoding="utf-8"), lock)
    args.output.write_text(prepared, encoding="utf-8")
    print("Prepared offline Sing-box 1.14.1 recipe; no package has been built.")


if __name__ == "__main__":
    main()
