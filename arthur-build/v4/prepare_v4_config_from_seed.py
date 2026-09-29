#!/usr/bin/env python3
"""Stage a V4 config preflight from the pinned qosmio NSS seed, offline only."""
import argparse
import re
from pathlib import Path

from prepare_candidate_config import merge

BASE_Y = (
    "TARGET_qualcommax", "TARGET_qualcommax_ipq60xx",
    "TARGET_qualcommax_ipq60xx_DEVICE_jdcloud_re-ss-01",
    "TARGET_ROOTFS_INITRAMFS", "TARGET_INITRAMFS_COMPRESSION_ZSTD",
    "PACKAGE_kmod-qca-nss-drv", "PACKAGE_kmod-qca-nss-ecm",
    "PACKAGE_kmod-ath11k", "PACKAGE_kmod-ath11k-ahb",
    "PACKAGE_ath11k-firmware-ipq6018", "PACKAGE_ipq-wifi-jdcloud_re-ss-01",
    "PACKAGE_wireless-regdb", "PACKAGE_iw", "PACKAGE_luci-mod-network",
    "PACKAGE_rpcd-mod-iwinfo", "PACKAGE_ethtool-full", "PACKAGE_iperf3",
)
BASE_N = (
    "TARGET_qualcommax_ipq807x", "ATH11K_MEM_PROFILE_512M",
    "ATH11K_MEM_PROFILE_256M", "ATH11K_NSS_SUPPORT",
    "ATH11K_NSS_MESH_SUPPORT", "NSS_FIRMWARE_VERSION_12_5",
    "NSS_FIRMWARE_VERSION_12_2",
)
SETTING = re.compile(r"^(?:CONFIG_([A-Za-z0-9_-]+)=|# CONFIG_([A-Za-z0-9_-]+) is not set$)")


def prepare(seed: str, candidate: str, core: str) -> str:
    if "CONFIG_TARGET_qualcommax=y" not in seed.splitlines() or "NSS" not in seed:
        raise ValueError("not the reviewed qosmio NSS seed")
    replacements = {key: f"CONFIG_{key}=y" for key in BASE_Y}
    replacements.update({key: f"# CONFIG_{key} is not set" for key in BASE_N})
    lines = [line for line in seed.splitlines()
             if not ((match := SETTING.match(line))
                     and (match.group(1) or match.group(2)) in replacements)]
    lines.extend(replacements.values())
    return merge(merge("\n".join(lines) + "\n", candidate), core)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", required=True, type=Path)
    ap.add_argument("--candidate", type=Path,
                    default=Path(__file__).with_name("candidate.config.fragment"))
    ap.add_argument("--core", type=Path,
                    default=Path(__file__).with_name("singbox-1.14.1.config.fragment"))
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    if args.output.exists():
        raise ValueError("refusing to overwrite an existing build config")
    args.output.write_text(prepare(args.seed.read_text(encoding="utf-8"),
                                   args.candidate.read_text(encoding="utf-8"),
                                   args.core.read_text(encoding="utf-8")), encoding="utf-8")


if __name__ == "__main__":
    main()
