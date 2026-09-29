#!/usr/bin/env python3
"""Prepare an offline 1.14.1 recipe from a pinned archive or Git object."""
import argparse
import hashlib
import json
import re
import subprocess
import tarfile
from pathlib import Path

OLD_VERSION = "PKG_VERSION:=1.14.0"
OLD_HASH = "PKG_HASH:=87baf6852e37941cbe40bdd94bec81c957c88a56751cecd6bbf0e6108bc69398"
REQUIRED_FEATURES = ("SINGBOX_WITH_QUIC", "SINGBOX_WITH_DHCP",
                     "SINGBOX_WITH_WIREGUARD", "SINGBOX_WITH_UTLS",
                     "SINGBOX_WITH_CLASH_API")
OLD_CONFFILES = """define Package/sing-box/conffiles
/etc/config/sing-box
/etc/sing-box/
endef

Package/sing-box-tiny/conffiles=$(Package/sing-box/conffiles)

"""
OLD_INSTALL = """define Package/sing-box/install
\t$(INSTALL_DIR) $(1)/usr/bin/
\t$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/sing-box $(1)/usr/bin/sing-box

\t$(INSTALL_DIR) $(1)/etc/sing-box
\t$(INSTALL_DATA) $(PKG_BUILD_DIR)/release/config/config.json $(1)/etc/sing-box

\t$(INSTALL_DIR) $(1)/etc/config/
\t$(INSTALL_CONF) ./files/sing-box.conf $(1)/etc/config/sing-box
\t$(INSTALL_DIR) $(1)/etc/init.d/
\t$(INSTALL_BIN) ./files/sing-box.init $(1)/etc/init.d/sing-box
endef"""
CORE_INSTALL = """# Arthur V4 packages the user's ported service/config separately.
# The upstream defaults would overwrite the existing custom service contract.
define Package/sing-box/install
\t$(INSTALL_DIR) $(1)/usr/bin/
\t$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/sing-box $(1)/usr/bin/sing-box
endef"""


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


def verify_checkout(checkout: Path, lock: dict) -> None:
    """Verify a pinned git object; the package download still checks PKG_HASH."""
    expected = lock["sing_box_source"]
    if expected["tag"] != "v1.14.1" or expected["go_mod_minimum"] != "1.25.5":
        raise ValueError("unreviewed Sing-box source metadata")

    def git(*args):
        try:
            return subprocess.run(["git", "-C", str(checkout), *args], check=True,
                                  capture_output=True, text=True, timeout=30).stdout.strip()
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            raise ValueError("cannot verify pinned Sing-box git object") from None

    if (git("rev-parse", "HEAD") != expected["revision"]
            or git("rev-parse", "refs/tags/" + expected["tag"] + "^{commit}")
            != expected["revision"]):
        raise ValueError("Sing-box checkout/tag revision mismatch")
    contents = git("show", "HEAD:go.mod")
    if (not re.search(r"^module github\.com/sagernet/sing-box$", contents, re.M)
            or not re.search(r"^go 1\.25\.5$", contents, re.M)):
        raise ValueError("unexpected Sing-box git object go.mod")


def adapt_makefile(original: str, lock: dict) -> str:
    source = lock["sing_box_source"]
    if source["tag"] != "v1.14.1" or source["revision"] != \
            "1ac1a339cb1223e9c70eae14c44411c75033c02d":
        raise ValueError("Sing-box source is not the pinned upstream v1.14.1")
    if original.count(OLD_VERSION) != 1 or original.count(OLD_HASH) != 1:
        raise ValueError("feed recipe changed; review it before updating")
    if not all(feature in original for feature in REQUIRED_FEATURES):
        raise ValueError("feed recipe lacks required build feature switches")
    if original.count(OLD_CONFFILES) != 1 or original.count(OLD_INSTALL) != 1:
        raise ValueError("feed service/config install changed; review ownership before updating")
    return (original.replace(OLD_VERSION, "PKG_VERSION:=1.14.1")
            .replace(OLD_HASH, "PKG_HASH:=" + source["codeload_sha256"])
            .replace(OLD_CONFFILES, "")
            .replace(OLD_INSTALL, CORE_INSTALL))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lock", type=Path, default=Path(__file__).with_name("feeds.lock.json"))
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--source-archive", type=Path)
    source.add_argument("--source-checkout", type=Path,
                        help="Pinned Git object; codeload hash still checked by make download")
    ap.add_argument("--feed-makefile", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True,
                    help="Prepared Makefile for an isolated V4 build tree")
    args = ap.parse_args()
    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    if args.source_archive:
        verify_archive(args.source_archive, lock)
    else:
        verify_checkout(args.source_checkout, lock)
    prepared = adapt_makefile(args.feed_makefile.read_text(encoding="utf-8"), lock)
    if args.output.exists():
        raise ValueError("refusing to overwrite an existing prepared recipe")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(prepared, encoding="utf-8")
    print("Prepared offline Sing-box 1.14.1 recipe; codeload hash/build still untested.")


if __name__ == "__main__":
    main()
