# 亚瑟 V4 新增页面交互契约（构建前草案）

现有中文 LuCI、Argon 和自定义 Sing-box 页面保持为基线。新增页面以只读状态和明确的设置入口起步；任何写入都须先通过对应的实机验证及恢复门禁。`luci-app-arthur-overview` 是这一契约的第一版实现，尚未编入镜像或在路由器运行。

该页面已准备独立测试包编译步骤，选择为 `m`，不加入镜像。产物检查核对页面、菜单和 ACL 与源码一致且权限只读；实际 APK 编译及 LuCI 运行仍待验证。正在运行的旧修订编译不包含本次新增步骤。

| 页面 | 状态数据 | 用户交互 | 写入开放条件 |
| --- | --- | --- | --- |
| 双 WAN | `mwan3.status(interfaces)`、`network.interface.dump` | 刷新、进入 LuCI mwan3 只读状态页；后续连接比例/健康监测/策略编辑 | 第二物理 WAN 端口映射、网关/DNS、firewall4/iptables、透明代理与 NSS 验证 |
| Mesh | `network.wireless.status` 中的 Mesh 接口 | 刷新、查看系统状态；后续节点列表和无线回程向导 | 两台实际设备组网、双频校准、无线回程与断线恢复验证 |
| NSS 与系统 | `system.info` 的运行时间、1/5/15 分钟负载、系统内存总量和可分配内存；NSS/ECM 计数器和温度接口待验证 | 刷新实际数据；内存不推断硬改容量，缺失字段显示未提供，NSS 保持未验证状态 | 确定真实计数器及测量方法，不能用模块已安装替代加速实测 |
| Sing-box 更新 | 本机核心版本、来源、运行状态、配置检查（待移植） | 上传或下载、预检、确认、重启服务、健康检查、失败回滚 | 新固件编译的核心及当前 UI 服务脚本已移植并实测 |

OpenClash 与自定义 Sing-box 均保留。透明代理后端选择必须互斥：切换前校验目标配置并保存原状态，停用原后端后才能启动目标后端；随后检查唯一活动后端、管理页面连通性和国内流量直连路径，任何一步失败都恢复原后端。升级迁移时默认不自动启用或切换代理后端。

切换命令报错不能推定服务状态未变。离线切换模型会清理已尝试启动的目标，并确认目标确实停用、没有冲突后端，才恢复配置和原服务。恢复后再次确认唯一活动后端、管理页面和国内直连；任一失败显示需人工恢复，不显示回滚成功。原服务仍在运行时不重复启动它；从停用状态切换失败也须确认管理页面可达。实际后端仍须实现事务锁、持久恢复状态和实机检查，此模型不能执行路由器操作。

当前页面只有读取状态和跳转现有只读 LuCI 状态页两种交互。它不生成配置、不重启服务、不触发刷写。`mwan3` 状态方法来自上游 LuCI 实现；网络与无线方法来自 OpenWrt ubus。NSS 和 Mesh 节点接口仍以实机证据为准，不从 DTS 或已安装模块推测。

各读取接口独立处理失败：无线读取失败显示“无法判断 Mesh 配置”，不显示“未发现 Mesh”；双 WAN 读取失败与成功返回空列表分别提示。刷新会替换此前状态，避免把旧数据当作当前数据。系统负载采用固定 LuCI 版本的 65535 换算系数，不显示为 CPU 百分比；零运行时间、零可分配内存都是有效值。ACL 仅增加 `system.info` 读取权限。

后续编辑动作统一采用：展示原配置与影响范围 → 保存候选配置 → 后端校验 → 应用并检查连通性 → 失败恢复旧配置。首次 4.4→6.12 升级及缺少 `rootfs_1` 的恢复问题仍由 OTA 门禁阻断。

上游接口：
- https://github.com/openwrt/luci/blob/0818828b3bf7ccc71f9a45a34873fb63826a2802/applications/luci-app-mwan3/htdocs/luci-static/resources/view/mwan3/status/overview.js
- https://openwrt.org/docs/guide-developer/ubus/network
- https://github.com/openwrt/luci/blob/0818828b3bf7ccc71f9a45a34873fb63826a2802/modules/luci-mod-status/htdocs/luci-static/resources/view/status/include/10_system.js
- https://github.com/openwrt/luci/blob/0818828b3bf7ccc71f9a45a34873fb63826a2802/modules/luci-mod-status/htdocs/luci-static/resources/view/status/include/20_memory.js
