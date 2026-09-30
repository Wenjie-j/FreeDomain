#!/usr/bin/env python3
"""Inspect an assembled V4 diagnostic image and emit metadata only."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import zipfile

from verify_components import inspect as inspect_components

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "arthur-upgrade"))
from upgrade_gate import evaluate, inspect_image


def one_file(directory: Path, pattern: str) -> Path:
    matches = list(directory.glob(pattern))
    if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file():
        raise ValueError("expected one regular diagnostic build artifact")
    return matches[0]


def build_report(target: Path, config: Path, root: Path, core_trace: dict,
                 owners: dict, openclash_trace: dict, inventory: dict) -> dict:
    if (target.is_symlink() or not target.is_dir()
            or root.is_symlink() or not root.is_dir()
            or config.is_symlink() or not config.is_file()):
        raise ValueError("missing or symlinked assembled image inputs")
    image = one_file(target, "*jdcloud_re-ss-01*-sysupgrade.bin")
    manifest = one_file(target, "*jdcloud_re-ss-01.manifest")
    image_report = inspect_image(image)
    upgrade = evaluate(inventory, image_report)
    with tempfile.TemporaryDirectory() as directory:
        component_input = Path(directory) / "diagnostic-manifest-and-config-only.zip"
        with zipfile.ZipFile(component_input, "w") as archive:
            archive.write(manifest, manifest.name)
            archive.write(config, "final.config")
        components = inspect_components(component_input, root, core_trace,
                                        owners, openclash_trace)
    digest = hashlib.sha256()
    with image.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "classification": "DIAGNOSTIC_IMAGE_BUILD_NOT_RELEASE_OR_FLASH_APPROVAL",
        "status": "DIAGNOSTIC_IMAGE_INSPECTED",
        "image_name": image.name,
        "image_bytes": image.stat().st_size,
        "image_sha256": digest.hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
        "assembled_components": components,
        "upgrade_gate": upgrade,
        "write_approved": False,
        "router_tested": False,
        "firmware_bytes_uploaded": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("target-dir", "config", "root-dir", "core-trace", "owners",
                 "openclash-trace", "inventory", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    report = build_report(
        args.target_dir, args.config, args.root_dir,
        json.loads(args.core_trace.read_text()), json.loads(args.owners.read_text()),
        json.loads(args.openclash_trace.read_text()), json.loads(args.inventory.read_text()))
    body = json.dumps(report, indent=2) + "\n"
    args.output.write_text(body)
    print(body, end="")


if __name__ == "__main__":
    main()
