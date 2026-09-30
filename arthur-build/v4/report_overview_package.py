#!/usr/bin/env python3
"""Audit the staged read-only LuCI payload and record its paired APK digest."""

import argparse
import hashlib
import json
from pathlib import Path


PACKAGE = "luci-app-arthur-overview"
FILES = {
    "www/luci-static/resources/view/arthur/overview.js":
        "htdocs/luci-static/resources/view/arthur/overview.js",
    "usr/share/luci/menu.d/luci-app-arthur-overview.json":
        "root/usr/share/luci/menu.d/luci-app-arthur-overview.json",
    "usr/share/rpcd/acl.d/luci-app-arthur-overview.json":
        "root/usr/share/rpcd/acl.d/luci-app-arthur-overview.json",
}
APK_FILE_LIST = f"lib/apk/packages/{PACKAGE}.list"
READ_UBUS = {
    "mwan3": ["status"], "network.interface": ["dump"],
    "network.wireless": ["status"], "system": ["info"],
}


def build_report(root: Path, apk: Path, config: Path, source: Path,
                 owners: dict, extracted: Path | None = None) -> tuple[dict, dict]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("missing or symlinked overview payload root")
    paths = list(root.rglob("*"))
    files = sorted(p.relative_to(root).as_posix() for p in paths if p.is_file())
    if files != sorted(FILES) or any(p.is_symlink() for p in paths):
        raise ValueError("unexpected overview payload files")
    hashes = {}
    for installed, original in FILES.items():
        actual, expected = root / installed, source / original
        if expected.is_symlink() or not expected.is_file():
            raise ValueError("missing or symlinked reviewed overview source")
        if actual.read_bytes() != expected.read_bytes():
            raise ValueError("installed overview differs from reviewed source")
        if actual.stat().st_mode & 0o111:
            raise ValueError("overview data file must not be executable")
        if installed in owners:
            raise ValueError("overview file ownership collision")
        hashes[installed] = hashlib.sha256(actual.read_bytes()).hexdigest()
    acl = json.loads((root / "usr/share/rpcd/acl.d/luci-app-arthur-overview.json").read_text())
    if (set(acl) != {PACKAGE} or set(acl[PACKAGE]) != {"description", "read"}
            or acl[PACKAGE]["read"] != {"ubus": READ_UBUS}):
        raise ValueError("overview ACL exceeds the read-only contract")
    menu = json.loads((root / "usr/share/luci/menu.d/luci-app-arthur-overview.json").read_text())
    if (set(menu) != {"admin/status/arthur"}
            or menu["admin/status/arthur"].get("action") != {"type": "view", "path": "arthur/overview"}
            or menu["admin/status/arthur"].get("depends") != {"acl": [PACKAGE]}):
        raise ValueError("overview menu differs from read-only entry")
    if f"CONFIG_PACKAGE_{PACKAGE}=m" not in config.read_text().splitlines():
        raise ValueError("overview trial must remain outside the image")
    if (apk.is_symlink() or not apk.is_file()
            or apk.name != f"{PACKAGE}-0.1-r1.apk" or not apk.stat().st_size):
        raise ValueError("expected overview APK missing")
    if extracted is not None:
        if extracted.is_symlink() or not extracted.is_dir():
            raise ValueError("missing or symlinked extracted APK root")
        extracted_paths = list(extracted.rglob("*"))
        extracted_files = sorted(p.relative_to(extracted).as_posix()
                                 for p in extracted_paths if p.is_file())
        expected_apk_files = sorted([*files, APK_FILE_LIST])
        if (extracted_files != expected_apk_files
                or any(p.is_symlink() or not (p.is_file() or p.is_dir())
                       for p in extracted_paths)):
            raise ValueError("unexpected files in extracted overview APK: "
                             f"expected {expected_apk_files}, got {extracted_files}")
        # OpenWrt writes this bookkeeping file after collecting the payload.
        # Permit exactly this file, and validate its contents rather than
        # ignoring the entire lib/apk directory.
        expected_list = "".join(f"/{name}\n" for name in files).encode()
        if (extracted / APK_FILE_LIST).read_bytes() != expected_list:
            raise ValueError("extracted APK package file list differs from payload")
        for installed in expected_apk_files:
            if (extracted / installed).stat().st_mode & 0o111:
                raise ValueError("extracted APK data file must not be executable")
        for installed in files:
            if (extracted / installed).read_bytes() != (root / installed).read_bytes():
                raise ValueError("extracted APK differs from staged overview")
    report = {
        "classification": "STAGED_LUCI_PAYLOAD_CHECK_NOT_IMAGE_OR_RUNTIME_APPROVAL",
        "package": PACKAGE,
        "package_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "staged_file_sha256": hashes,
        "staged_package_files": files,
        "ubus_read_methods": READ_UBUS,
        "status": "READ_ONLY_STAGED_PAYLOAD_VERIFIED",
        "apk_payload_independently_extracted": extracted is not None,
        "apk_bookkeeping_sha256": ({APK_FILE_LIST: hashlib.sha256(
            (extracted / APK_FILE_LIST).read_bytes()).hexdigest()}
            if extracted is not None else {}),
        "luci_runtime_verified": False,
        "firmware_inclusion_approved": False,
    }
    merged = dict(owners)
    merged.update({name: [PACKAGE] for name in files})
    return report, merged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package-root", "apk", "config", "source", "owners", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--apk-extracted-root", type=Path)
    args = parser.parse_args()
    report, owners = build_report(args.package_root, args.apk, args.config, args.source,
                                 json.loads(args.owners.read_text()), args.apk_extracted_root)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "v4-overview-package-build.json").write_text(json.dumps(report, indent=2) + "\n")
    (args.output_dir / "v4-package-file-owners.partial.json").write_text(json.dumps(owners, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
