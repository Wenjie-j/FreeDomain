# 私有节点端点输入（离线集成阶段）

`proxy_endpoint_inventory.py` 从候选 Sing-box JSON 的所有服务器出站提取
端点，包含 selector/urltest 未选中的节点和 detour 节点。它不读取节点密码
作为输出，不联网，不执行 Sing-box，也不修改路由器。真正的配置合法性
仍须由目标 Sing-box 1.14.1 的 `check` 独立验证。

支持显式 `server`/`server_port` 的 socks、http、shadowsocks、vmess、vless、
trojan、hysteria、hysteria2、tuic、anytls、shadowtls、ssh、naive。仅忽略无
服务器字段的 direct、selector、urltest。其他类型及非空 `endpoints` 必须
先实现并审阅适配，不能静默跳过 WireGuard/Tailscale 等端点。所有代理服务器
须为公网 IPv4 或 ASCII 域名，端口须明确；IPv6 或本地代理链需要单独方案。

## 域名快照

有域名的配置必须提供由后续私有解析适配器生成的快照：

| 字段 | 条件 |
| --- | --- |
| `config_sha256` | 对完整候选配置原始字节计算的 SHA-256，配置变化后旧快照失效 |
| `captured_at` | 非负整数 Unix 秒；不能在未来；当前时间减该值小于 900 秒 |
| `records` | 键恰好是配置内全部规范化域名，小写且去除一个尾部点 |
| `records[域名].ipv4` | 非空公网 IPv4 列表；不能有 IPv6、私网或共享地址 |
| `records[域名].expires_at` | 非负整数 Unix 秒；大于当前时间，且不超过采集时间加 900 秒 |

适配器应使用实际 DNS TTL 与 900 秒上限中的较早期限，处理 CNAME 最短有效期；
不得为方便通过校验延长 TTL。快照只证明输入绑定和有效期检查，不证明 DNS
答案真实或完整。受限的离线解析和快照原子刷新已实现，详情见下文；定时刷新、目标核心使用相同答案的约束、
实时规则替换与配置切换事务仍待 B2 运行集成。不能把该离线工具当作已经解决 DNS 竞态。

## 候选生成

`prepare_cn_firewall_candidate.py` 保留手动重复 `--proxy-endpoint-ipv4` 的方式，
也支持互斥的 `--singbox-config` 和可选 `--endpoint-snapshot`。
域名快照缺失、过期、与候选配置不匹配、漏域名或包含非公网答案时拒绝生成。
国内规则解码后再次核验最早到期时间，过期时不会发布候选文件。

只含 IPv4 字面量的配置不需要快照。程序对地址去重并排序，交给已有渲染器
在 TCP 和 UDP 两条链中生成相同的节点绕过规则。stdout 仅输出数量、有效期与
离线检查状态，不输出节点名称、端点地址或认证信息。配置、快照和生成的
nft 文件均为私有材料；生成文件不覆盖已有文件。最终安装仍需要目标
`fw4 check`、后端切换与恢复条件。

源码依据（固定 Sing-box 1.14.1 来源）：
- https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/option/outbound.go
- https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/option/simple.go
- https://github.com/SagerNet/sing-box/blob/1ac1a339cb1223e9c70eae14c44411c75033c02d/option/wireguard.go

## 离线 DNS 解析适配器

`refresh_proxy_dns_snapshot.py` 接收私有配置、显式公网 IPv4 解析器和快照输出
路径，使用执行主机的 BIND `dig` 查询每个域名的 A 记录。它关闭用户 digrc、
搜索后缀和 EDNS，指定完整域名及输出格式；不执行 shell 拼接。最多处理 128 个
不同域名，每次命令最多 5 秒，总查询预算 45 秒。它只刷新快照文件，不启动
路由器服务、不安装防火墙、不安排定时任务，也不新增目标固件的 Python/BIND 依赖。

响应须匹配请求域名，状态为 NOERROR、非截断且答案计数一致。拒绝空答案、
非公网或 IPv6 答案、缺失末端 A 记录、别名循环/歧义及无关答案。沿最多 16 个
名字的 CNAME 链收集全部终端 A 地址，采用链和地址集合的最短 TTL，最多保留
900 秒。有效期从查询前计时，查询耗时不会额外延长 TTL；整个批次结束与保存前
都会检查有效期和候选配置原始字节。

先获取快照独占锁，完成全部解析和校验后写入权限 0600 的临时文件，再原子
替换快照。查询失败、解析过期、配置变化或替换失败均保留上一次文件。
外部写入已经修改的快照不被覆盖；已有锁不被自动删除。进程异常终止留下的锁
需要独立检查，不据此开放目标服务写入。

保留旧文件仅用于保存上次结果，不延长其有效期，也不保证旧规则对应的连接
仍然可用。旧快照到期后，`collect` 仍会拒绝将其用于新候选。DNS 来源一致性、
解析器可信性和目标核心实际使用同一组地址尚未通过实机验证。

自动测试包含受控响应的故障与失败保留场景，以及真实 BIND dig 通过回环地址
读取模拟 DNS 服务的 CNAME/多地址响应。该测试不查询用户实际节点或外部 DNS。

参考：
- https://bind9.readthedocs.io/en/v9.18.39/manpages.html#dig-dns-lookup-utility
- https://www.rfc-editor.org/rfc/rfc2181.html
