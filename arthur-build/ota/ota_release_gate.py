#!/usr/bin/env python3
"""Read-only Arthur sysupgrade artifact checker. Never writes router partitions.

ALWAYS emits NO_GO for production. This checker cannot prove hardware boot,
rollback, dynamic 1GiB DRAM detection or full config migration.
"""
import argparse
import hashlib
import io
import json
import struct
import sys
import tarfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "arthur-upgrade"))
from fit_integrity import verify_fit

NEEDS = (
    "hlos_1_boot_verified",
    "rootfs_1_present",
    "backup_gpt_valid",
    "independent_recovery_verified",
    "bootloader_automatic_rollback_verified",
    "first_migration_config_converter_verified",
    "linux_612_runtime_1g_wifi_nss_verified",
)

def inspect(artifact, baseline):
    report = {
        "artifact": Path(artifact).name,
        "classification": "RESEARCH_ONLY_NOT_FLASH_APPROVAL",
        "static_checks": {}, "hard_blockers": [],
        "warnings": [
            "FIT magic/marker checks do not replace full FIT subimage/hash verification.",
            "No hardware boot, bootloader fallback, or cross-version config migration has been proved.",
            "DO NOT run sysupgrade, dd, fw_setenv, or modify GPT on the live router.",
        ],
        "decision": "NO_GO_FOR_PRODUCTION_ROUTER",
    }
    c = report["static_checks"]
    with zipfile.ZipFile(artifact, "r") as z:
        images = [n for n in z.namelist() if n.endswith("-squashfs-sysupgrade.bin")]
        if len(images) != 1:
            raise ValueError("expected exactly one squashfs sysupgrade image")
        info = z.getinfo(images[0])
        if info.file_size > 256 * 1024 * 1024:
            raise ValueError("sysupgrade image too large")
        payload = z.read(info)
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as tf:
        files = [m for m in tf.getmembers() if m.isfile()]
        kernels = [m for m in files if m.name.startswith("sysupgrade-") and m.name.endswith("/kernel")]
        roots = [m for m in files if m.name.startswith("sysupgrade-") and m.name.endswith("/root")]
        if len(kernels) != 1 or len(roots) != 1:
            raise ValueError("expected exactly one kernel and one rootfs in sysupgrade")
        k, root = kernels[0], roots[0]
        if k.size > 32 * 1024 * 1024 or k.size < 1024:
            raise ValueError("implausible FIT size")
        kernel = tf.extractfile(k).read()
        root_magic = tf.extractfile(root).read(4)
    if kernel[:4] != b"\xd0\x0d\xfe\xed":
        raise ValueError("FIT signature invalid")
    size = struct.unpack_from(">I", kernel, 4)[0]
    if size != len(kernel):
        raise ValueError("FIT declared length disagrees with actual length")
    c["fit_bytes"] = size
    c["fit_sha256"] = hashlib.sha256(kernel).hexdigest()
    try:
        c["fit_subimage_hash_algorithms"] = verify_fit(kernel)
        c["fit_subimage_hashes_valid"] = True
    except ValueError:
        c["fit_subimage_hash_algorithms"] = []
        c["fit_subimage_hashes_valid"] = False
    c["hlos_capacity_bytes"] = int(baseline["hlos_partition_bytes"])
    c["hlos_headroom_bytes"] = c["hlos_capacity_bytes"] - size
    c["kernel_fits_hlos"] = 0 < size <= c["hlos_capacity_bytes"]
    c["rootfs_bytes"] = root.size
    c["rootfs_capacity_bytes"] = int(baseline["rootfs_partition_bytes"])
    c["rootfs_fits_partition"] = 0 < root.size <= c["rootfs_capacity_bytes"]
    c["rootfs_is_squashfs"] = root_magic == b"hsqs"
    for label, marker in (
        ("fit_config_cp03_c2_present", b"config@cp03-c2"),
        ("target_board_re_ss_01_present", b"jdcloud,re-ss-01"),
        ("wifi_cal_variant_present", b"JDC-RE-SS-01"),
    ):
        c[label] = marker in kernel
    if not all(v for v in c.values() if isinstance(v, bool)):
        report["hard_blockers"].append("STATIC_ARTIFACT_LAYOUT_OR_IDENTITY_CHECK_FAILED")
    for need in NEEDS:
        if baseline.get(need) is not True:
            report["hard_blockers"].append("UNVERIFIED_" + need.upper())
    return report

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--artifact", required=True, type=Path)
    ap.add_argument("--baseline", required=True, type=Path)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args(argv)
    try:
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        report = inspect(args.artifact, baseline)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile) as err:
        report = {
            "artifact": args.artifact.name,
            "classification": "RESEARCH_ONLY_NOT_FLASH_APPROVAL",
            "decision": "NO_GO_INVALID_ARTIFACT",
            "hard_blockers": [str(err)],
        }
    result = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    print(result, end="")
    return 2

if __name__ == "__main__":
    sys.exit(main())
