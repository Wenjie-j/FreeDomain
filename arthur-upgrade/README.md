# 亚瑟 1GB：无感网页升级工程（第一道只读安全门禁）

## 用户体验，不改变
目标沿用现有 iStoreOS LuCI 页面：上传本机固件 → 自动校验 → 显示迁移清单和备份状态 → 用户确认 → 系统升级/重连；成功后原 LAN 地址、节点配置、DNS 和自定义管理页应恢复；后续同系列小版本升级复用相同网页。
这是最终产品需求，不是当前 V3 已实现的能力。**不要求用户购买串口或拆机。**

## 从用户设备实际备份确认的风险
- 机型 JDCloud AX1800_Pro IPQ6018/AP-CP03-C1，1GiB RAM，当前 Linux 4.4.60/QWRT R24.5.20。
- p16 HLOS=6MiB、p17 HLOS_1=6MiB（尚未验证可启动）、p18 rootfs=2GiB、没有 rootfs_1；备用 GPT 未验证为有效。
- 旧系统 platform_check_image() 直接返回 0；AX1800_Pro 的 mmc_do_flash 会依次写入现用 HLOS 和现用 rootfs，随后重建 overlay。这不是具有自动回滚保证的 A/B 更新。
- V3 上游新脚本根据 BOOTCONFIG 选择 HLOS/HLOS_1 及 rootfs/rootfs_1，不能直接用于缺失 rootfs_1 的实机；eMMC 实现存在写 rootfs 前清除目标 FIT 头的代码。
- V3 真实 FIT 大小 5,674,292 bytes（剩余 617,164 bytes），rootfs 镜像 14,880,768 bytes；FIT 容量已验收，1GiB 正式启动、NSS/Wi-Fi/用户全部代理能力和恢复尚未实机验收。

## 当前脚本的用途和限制
upgrade_gate.py 只读取一份离线固件 sysupgrade tar 和固定的硬件清单，检查 FIT 体积、镜像板型字符串、内核与设备树子镜像的 FIT 内部哈希、SquashFS 文件头、分区容量与升级安全条件；输出 JSON 并对当前原机返回退出码 2（BLOCKED）。已保存的 V3 真实镜像通过其 CRC32/SHA1 子镜像哈希检查，但这不是发布者签名校验，也不能证明实际能启动。
新增的设备树内存检查会阻断明写 512MiB 的 FIT。原机 p16 FIT 声明 512MiB，而运行时 FDT 为 1GiB；V3 FIT 没有显式内存节点，离线检查结果是 `BOOTLOADER_DEPENDENT_NO_MEMORY_NODE`，仍保持阻断。只有新内核实际启动后读取运行时 FDT，才能确认这次内存传递是否正常。
它不连接用户路由器，不读写真实 GPT/HLOS/rootfs/U-Boot 环境；即使人为修改所有 inventory flags 为 true，脚本仍禁止自行批准刷机，直到另行实现并审核签名发布和受支持的恢复机制。

用法：python3 arthur-upgrade/upgrade_gate.py --inventory arthur-upgrade/inventory-arthur-1gb-v3.json --sysupgrade /path/to/sysupgrade.bin --network-report /path/to/sanitized-network-report.json --output report.json

V4 的 `arthur-build/v4/legacy_network_preflight.py` 可从离线旧 `uci show` 生成脱敏的网络报告；本门禁会把已知网络迁移阻断项合并进固件检查。缺少报告或报告格式异常也会阻断。它不会自动转换接口，更不会因为已有报告而批准刷写。

## 后续研发门槛
1. 设计并实证首次跨 4.4→6.12 的升级/恢复路径，明确缺少 rootfs_1 时是否能够满足真正自动回滚；如果不能，必须向用户如实说明首次升级残余风险，不用 UI 样式掩饰。
2. 编写升级前配置白名单/依赖映射：旧 opkg/iptables/IPSET/QCA Wi-Fi → 新 apk/fw4/nftables/ath11k；原 Sing-box、自定义 LuCI 页面、WAN/LAN/IPTV 和 DNS 由迁移器单独处理。
3. 编译集成需要的 kmod-tun 和用户界面，验证 1GiB 运行 FDT、无线校准、NSS/ECM 性能；双 WAN、Mesh 分层验收。
4. 开发在 LuCI 中的 *先审计、后确认、受控写盘* 事务式操作和启动自检；不把一个 sysupgrade 命令直接包成“安全一键升级”。

源码参考：
- 新系统亚瑟升级分支：https://github.com/qosmio/openwrt-ipq/blob/92a2d104145c8d265851c4b388a41bd8e9c21cd9/target/linux/qualcommax/ipq60xx/base-files/lib/upgrade/platform.sh
- 新系统 eMMC 写入：https://github.com/qosmio/openwrt-ipq/blob/92a2d104145c8d265851c4b388a41bd8e9c21cd9/package/base-files/files/lib/upgrade/emmc.sh
- 已成功编译的 V3：https://github.com/Wenjie-j/FreeDomain/actions/runs/36417540760
