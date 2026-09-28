# 亚瑟 V4 新增页面交互契约（构建前草案）

现有中文 LuCI、Argon 和自定义 Sing-box 页面保持为基线。新增页面以只读状态和明确的设置入口起步；任何写入都须先通过对应的实机验证及恢复门禁。`luci-app-arthur-overview` 是这一契约的第一版实现，尚未编入镜像或在路由器运行。

| 页面 | 状态数据 | 用户交互 | 写入开放条件 |
| --- | --- | --- | --- |
| 双 WAN | `mwan3.status(interfaces)`、`network.interface.dump` | 刷新、进入 LuCI mwan3 只读状态页；后续连接比例/健康监测/策略编辑 | 第二物理 WAN 端口映射、网关/DNS、firewall4/iptables、透明代理与 NSS 验证 |
| Mesh | `network.wireless.status` 中的 Mesh 接口 | 刷新、查看系统状态；后续节点列表和无线回程向导 | 两台实际设备组网、双频校准、无线回程与断线恢复验证 |
| NSS 与系统 | 新固件上的 NSS/ECM 运行计数器、内存、温度（待确定可用接口） | 刷新；区分有线 NSS、Wi-Fi 普通路径与未验证状态 | 确定真实计数器及测量方法，不能用模块已安装替代加速实测 |
| Sing-box 更新 | 本机核心版本、来源、运行状态、配置检查（待移植） | 上传或下载、预检、确认、重启服务、健康检查、失败回滚 | 新固件编译的核心及当前 UI 服务脚本已移植并实测 |

当前页面只有读取状态和跳转现有只读 LuCI 状态页两种交互。它不生成配置、不重启服务、不触发刷写。`mwan3` 状态方法来自上游 LuCI 实现；网络与无线方法来自 OpenWrt ubus。NSS 和 Mesh 节点接口仍以实机证据为准，不从 DTS 或已安装模块推测。

后续编辑动作统一采用：展示原配置与影响范围 → 保存候选配置 → 后端校验 → 应用并检查连通性 → 失败恢复旧配置。首次 4.4→6.12 升级及缺少 `rootfs_1` 的恢复问题仍由 OTA 门禁阻断。

上游接口：
- https://github.com/openwrt/luci/blob/0818828b3bf7ccc71f9a45a34873fb63826a2802/applications/luci-app-mwan3/htdocs/luci-static/resources/view/mwan3/status/overview.js
- https://openwrt.org/docs/guide-developer/ubus/network
