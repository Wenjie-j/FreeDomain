# Arthur 1GiB: firmware OTA release contract (2026-09-28)

**Research state: V3 is NOT approved for flashing or one-click sysupgrade.**

User acceptance criteria: retain the existing Chinese LuCI upload/confirm/reboot workflow; keep all user node databases, custom Sing-box LuCI QR rename/scan and tests, domestic-bypass NSS, firewall/DNS, Wi-Fi, WAN config, optional OpenClash; preserve 1GiB RAM, Wi-Fi calibration, and allow independently upgradeable Sing-box with rollback. Add dual WAN failover/load balancing and Mesh only after testing. Do not require buying USB-TTL hardware, serial console, dismantling hardware, or command-line procedures.

## Audited source facts

1. Real old backup (2026-09-27) `rom/lib/upgrade/platform.sh`: `platform_check_image() { return 0; }`; AX1800_Pro selects `0:HLOS` and `rootfs`, and calls `mmc_do_upgrade`.
2. Same backup `rom/lib/upgrade/mmc.sh`: `mmc_do_flash` overwrites both active kernel and active rootfs and creates new overlay; this implementation does **not** ensure automatic restore of the full previous firmware after a failed boot.
3. Observed GPT: p16 HLOS 6MiB, p17 HLOS_1 6MiB but **not validated as bootable**, p18 rootfs 2GiB, **no rootfs_1**; backup GPT invalid/missing.
4. Pinned upstream qosmio/openwrt-ipq@92a2d104145c8d265851c4b388a41bd8e9c21cd9 `platform.sh`: also has `platform_check_image return 0`; for `jdcloud,re-ss-01` reads BOOTCONFIG offset 148 and conditionally selects `HLOS_1/rootfs_1` or `HLOS/rootfs`, then `emmc_do_upgrade`. This is **not yet compatible with the user's storage layout**.
5. Successful V3 Run https://github.com/Wenjie-j/FreeDomain/actions/runs/36417540760 has kernel FIT 5,674,292 bytes (< 6MiB), but no verification of boot safety, effective 1GiB FDT, full NSS/Mesh, or integrated Sing-box stack.

## Release gates

- **P0 boot-storage safety**: Match exact board, reserved-memory, FIT capacity, full FIT subimage hashes, live boot slot, physical partition layout, rootfs data format, image root/kernel sizes, GPT validity. Establish a VERIFIED independently bootable fallback or real A/B pair with bootloader bootcount/fallback before claiming automated rollback. Without such evidence **block release, do not offer a bypass**. Do not write ART/CDT/GPT in speculative tests.
- **P1 first migration**: Build and test a white-listed config translation from legacy opkg + iptables/ipset + qcawificfg80211 to current apk + fw4/nftables + ath11k, preserve LAN IP/DHCP/WAN/SSIDs/PSKs/Sing-box rules/UI/network control; do not blindly restore old sysupgrade.tgz just because LuCI has a checked retain-settings box.
- **P2 maintenance upgrade**: Future upgrades use the same LuCI UI; preflight→backup→upgrade→boot health checks→confirmation/fallback only when bootloader and storage support it. Retain working NSS and network performance. Sing-box binary/GUI/rules have separate signed/hash-checked upgrade/rollback channels. Validate dual WAN without fwmark 0x66/table166 conflicts and Mesh without claiming untested NSS WLAN offload.

### Operational rule

One-click web UX is a **product requirement**, not proof of fail-safe behavior. First legacy-to-modern migration and later within-family upgrades are distinct. If the existing physical layout prevents unattended rollback, prefer preserving the old router rather than giving the user a deceptively simple upload button. Serial/TFTP is **not** a mandatory user step and must never be inserted into the acceptance criteria.

The latest user-owned offline audit, unit tests, and blocking decision are archived under `/路由器备份/Arthur-OTA-只读预检和实测-20260928.zip` in ChatGPT Library. They currently output `NO_GO_FOR_PRODUCTION_ROUTER` for the real V3 image even though FIT size checks pass.
