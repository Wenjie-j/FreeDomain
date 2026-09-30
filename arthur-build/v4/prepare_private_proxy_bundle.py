#!/usr/bin/env python3
"""Build and recheck a private, offline proxy-rule review bundle.

Never install, reload, switch a proxy backend, or upload a bundle. The copied
Sing-box config may contain credentials. Only synthetic fixtures belong in CI.
"""

import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
from pathlib import Path

from prepare_cn_firewall_candidate import prepare
from proxy_endpoint_inventory import collect, private_bytes, strict_json

CONFIG = "singbox-config.json"
SNAPSHOT = "endpoint-snapshot.json"
CN_SRS = "geoip-cn.srs"
NFT = "candidate.nft"
MANIFEST = "PRIVATE-REVIEW.json"
MAX_SRS = 16 * 1024 * 1024
PACKAGE = "PRIVATE_OFFLINE_PROXY_RULE_BUNDLE_NOT_INSTALL_APPROVAL"


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def safe_regular(path: Path, max_bytes: int, minimum: int = 1) -> bytes:
    if (path.is_symlink() or any(part.is_symlink() for part in path.parents)
            or not path.is_file() or not stat.S_ISREG(path.stat().st_mode)):
        raise ValueError("private source must be a regular non-symlinked file")
    size = path.stat().st_size
    if not minimum <= size <= max_bytes:
        raise ValueError("private source size outside bounds")
    raw = path.read_bytes()
    if not minimum <= len(raw) <= max_bytes:
        raise ValueError("private source size outside bounds")
    return raw


def _destination(path: Path):
    if path.is_symlink() or path.exists() or any(part.is_symlink() for part in path.parents):
        raise ValueError("private bundle destination already exists or has a symlink")
    if path.name in ("", ".", ".."):
        raise ValueError("invalid private bundle destination")


def _write_private(path: Path, raw: bytes):
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(0o600)


def _time(now) -> int:
    value = int(time.time()) if now is None else now
    if type(value) is not int or value < 0:
        raise ValueError("invalid review time")
    return value


def audit(root: Path, binary: Path, *, now: int | None = None,
          reproduce: bool = True) -> dict:
    requested_now = now
    now = _time(now)
    if (root.is_symlink() or any(parent.is_symlink() for parent in root.parents)
            or not root.is_dir() or root.stat().st_mode & 0o077):
        raise ValueError("private bundle root must have restricted permissions")
    present = {path.name for path in root.iterdir()}
    expected = {CONFIG, CN_SRS, NFT, MANIFEST}
    if SNAPSHOT in present:
        expected.add(SNAPSHOT)
    if present != expected:
        raise ValueError("unexpected private bundle file set")
    for name in expected:
        path = root / name
        if (path.is_symlink() or not path.is_file()
                or not stat.S_ISREG(path.stat().st_mode)
                or path.stat().st_mode & 0o077):
            raise ValueError("private bundle payload file is not restricted")
    manifest = strict_json(private_bytes(root / MANIFEST))
    if (not isinstance(manifest, dict)
            or set(manifest) != {"classification", "payload_sha256", "lan_iface",
                                 "config_sha256", "dns_valid_until",
                                 "endpoint_ipv4_count", "cn_ipv4_cidr_count",
                                 "binary_sha256", "status",
                                 "target_service_checked", "router_install_approved"}
            or manifest["classification"] != PACKAGE
            or manifest["status"] != "OFFLINE_BUNDLE_VERIFIED"
            or manifest["router_install_approved"] is not False
            or manifest["target_service_checked"] is not False):
        raise ValueError("private bundle audit contract mismatch")
    payload = manifest["payload_sha256"]
    if (not isinstance(payload, dict) or set(payload) != expected - {MANIFEST}
            or any(not isinstance(value, str) or len(value) != 64
                   for value in payload.values())):
        raise ValueError("private bundle payload manifest mismatch")
    blobs = {name: safe_regular(root / name, MAX_SRS if name == CN_SRS else 2 * 1024 * 1024)
             for name in expected - {MANIFEST}}
    if any(digest(data) != payload[name] for name, data in blobs.items()):
        raise ValueError("private bundle payload digest mismatch")
    config = blobs[CONFIG]
    snapshot = blobs.get(SNAPSHOT)
    endpoints, endpoint_report = collect(config, snapshot, now=now)
    if (manifest["config_sha256"] != digest(config)
            or manifest["dns_valid_until"] != endpoint_report["dns_snapshot_valid_until"]
            or manifest["endpoint_ipv4_count"] != len(endpoints)):
        raise ValueError("private bundle config and DNS binding mismatch")
    core = safe_regular(binary, 128 * 1024 * 1024)
    if manifest["binary_sha256"] != digest(core):
        raise ValueError("private bundle converter binary mismatch")
    if reproduce:
        with tempfile.TemporaryDirectory(prefix="arthur-bundle-verify-") as directory:
            checked = Path(directory) / NFT
            report = prepare(binary, root / CN_SRS, manifest["lan_iface"],
                             endpoints, checked, endpoint_report["dns_snapshot_valid_until"])
            if (report["cn_ipv4_cidr_count"] != manifest["cn_ipv4_cidr_count"]
                    or checked.read_bytes() != blobs[NFT]):
                raise ValueError("private bundle nft rule reproduction differs")
        # Validation may have taken long enough for an address to expire.
        collect(config, snapshot, now=_time(None) if requested_now is None else now)
    return {"classification": PACKAGE, "status": "OFFLINE_BUNDLE_VERIFIED",
            "source_file_count": len(payload),
            "proxy_endpoint_ipv4_count": len(endpoints),
            "cn_ipv4_cidr_count": manifest["cn_ipv4_cidr_count"],
            "dns_valid_until": endpoint_report["dns_snapshot_valid_until"],
            "rule_bytes_reproduced": reproduce,
            "target_service_checked": False, "router_install_approved": False}


def build(binary: Path, srs: Path, config: Path, snapshot: Path | None,
          lan_iface: str, output: Path, *, now: int | None = None) -> dict:
    _destination(output)
    _time(now)
    inputs = {CONFIG: private_bytes(config), CN_SRS: safe_regular(srs, MAX_SRS, 100)}
    if snapshot is not None:
        inputs[SNAPSHOT] = private_bytes(snapshot)
    endpoints, endpoint_report = collect(inputs[CONFIG], inputs.get(SNAPSHOT), now=now)
    core = safe_regular(binary, 128 * 1024 * 1024)
    if not binary.stat().st_mode & 0o111:
        raise ValueError("converter must be an executable regular file")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".arthur-private-review-", dir=output.parent))
    try:
        for name, data in inputs.items():
            _write_private(stage / name, data)
        report = prepare(binary, stage / CN_SRS, lan_iface,
                         endpoints, stage / NFT, endpoint_report["dns_snapshot_valid_until"])
        files = dict(inputs, **{NFT: (stage / NFT).read_bytes()})
        manifest = {
            "classification": PACKAGE,
            "payload_sha256": {name: digest(data) for name, data in files.items()},
            "lan_iface": lan_iface,
            "config_sha256": digest(inputs[CONFIG]),
            "dns_valid_until": endpoint_report["dns_snapshot_valid_until"],
            "endpoint_ipv4_count": len(endpoints),
            "cn_ipv4_cidr_count": report["cn_ipv4_cidr_count"],
            "binary_sha256": digest(core),
            "status": "OFFLINE_BUNDLE_VERIFIED",
            "target_service_checked": False, "router_install_approved": False,
        }
        _write_private(stage / MANIFEST, (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode())
        def unchanged_sources():
            for name, source in ((CONFIG, config), (CN_SRS, srs), (SNAPSHOT, snapshot)):
                if source is not None and safe_regular(source, MAX_SRS if name == CN_SRS
                                                      else 2 * 1024 * 1024) != inputs[name]:
                    raise ValueError("private input changed during bundle creation")
            if safe_regular(binary, 128 * 1024 * 1024) != core:
                raise ValueError("converter binary changed during bundle creation")
        unchanged_sources()
        audit(stage, binary, now=now)
        # Re-evaluate freshness and source identity after the reproducing audit.
        collect(inputs[CONFIG], inputs.get(SNAPSHOT), now=int(time.time()) if now is None else now)
        unchanged_sources()
        _destination(output)
        os.rename(stage, output)
        return {"classification": PACKAGE, "status": "OFFLINE_BUNDLE_VERIFIED",
                "source_file_count": len(inputs), "proxy_endpoint_ipv4_count": len(endpoints),
                "cn_ipv4_cidr_count": report["cn_ipv4_cidr_count"],
                "dns_valid_until": endpoint_report["dns_snapshot_valid_until"],
                "target_service_checked": False, "router_install_approved": False}
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", type=Path, required=True)
    parser.add_argument("--geoip-cn-srs", type=Path, required=True)
    parser.add_argument("--singbox-config", type=Path, required=True)
    parser.add_argument("--endpoint-snapshot", type=Path)
    parser.add_argument("--lan-iface", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = build(args.sing_box, args.geoip_cn_srs, args.singbox_config,
                   args.endpoint_snapshot, args.lan_iface, args.output_dir)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
