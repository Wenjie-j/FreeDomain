# JDCloud AX1800 Pro / RE-SS-01 — Arthur NSS V1

This isolated branch is only for building a **RAM-boot initramfs test image** for the user's JDCloud AX1800 Pro (AP-CP03-C1 / RE-SS-01 class).

Safety goals:
- Do not change GPT.
- Do not write HLOS/HLOS_1/rootfs.
- Do not flash the build output yet.
- First validate Ethernet, Wi-Fi, ART/caldata, NSS/ECM and eMMC from RAM boot.

Upstream source: `qosmio/openwrt-ipq`, branch `main-nss`, pinned at:
`92a2d104145c8d265851c4b388a41bd8e9c21cd9`

Target:
- `qualcommax/ipq60xx`
- `jdcloud_re-ss-01`

The workflow publishes build metadata and target images as a GitHub Actions artifact named `arthur-nss-initramfs`.
