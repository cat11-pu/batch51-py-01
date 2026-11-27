# batch51-py-safety-c-32

## 题面

图片代理上线第二天，内网监控就报有人从公网把本机管理页整页读走了。回放请求，用户提交的地址写成十进制整数 2130706433，也出现过 0177.0.0.1 和 0x7f.0.0.1，网关按字符串前缀比对，三种写法一个都没拦住；另一条更麻烦，提交的是我们自己的图片域名，判定那一刻解析到公网地址按放行处理，真正发起请求时该域名已经指向 10 段的接口机，取回的是内网数据。还有客户投诉跳转被跟丢了：短链跳到第二个地址后就不再校验，后面几跳去了哪里没人知道。范围是 gsb/batch51-py-safety-c-32 下的 ssrf_target_resolver.py，类 SsrfTargetResolver，负责把提交地址归一为可判定目标、在判定时点绑定解析结果、并逐跳复核跳转。

公开接口：SsrfTargetResolver(*, schemes=("http","https"), allow_hosts=(), deny_cidrs=(), max_redirects=3, max_targets=64)；normalize(raw)；classify_scope(address)；bind_resolution(host, addresses, *, now=None)；decide(raw, *, addresses=None, now=None)；authorize_request(target, *, addresses=None, now=None)；follow_redirect(target, location, *, now=None)；hops_for(target)；allow_host(host)；allowed_hosts()；targets()；snapshot()；restore(state)；stats()。拒绝时抛 SsrfError(code, detail)，code 为大写串。

要修的行为：① normalize 把 scheme 与 host 转小写、去掉默认端口和 host 末尾的点，path 缺省为 "/"，canonical 拼成 scheme://host[:port]/path 且省略默认端口；缺 scheme、空串、非字符串抛 SSRF_INVALID_TARGET；scheme 不在允许集合内抛 SSRF_SCHEME_DENIED；② 十进制整数、带前导零的八进制、0x 十六进制三种 IPv4 写法统一换算成点分四段，canonical 使用换算后的地址；③ classify_scope 只接受地址字面量：10/8、172.16/12、192.168/16、fd00::/8 判 private，127/8 与 ::1 判 loopback，169.254/16 与 fe80::/10 判 link_local，169.254.169.254、100.100.100.200、fd00:ec2::254 单列 metadata，映射进 IPv6 的 v4 按内嵌地址判，其余公网地址判 public，非地址字面量判 invalid；④ decide 先归一再判范围，public 放行，private、loopback、link_local、metadata 回 SSRF_SCOPE_DENIED，返回 {"target","verdict","reason","scope"}；⑤ deny_cidrs 命中直接 SSRF_HOST_DENIED 且优先于白名单，allow_hosts 命中放行、reason 为 allowlisted、不再看解析结果；⑥ 未命中白名单但带了解析结果时，任一地址落在非公网段回 SSRF_RESOLVED_PRIVATE，scope 取最严重的那一个；⑦ bind_resolution 归一主机名并对地址去重升序，bound_at 记判定时点，地址为空抛 SSRF_RESOLUTION_EMPTY；⑧ follow_redirect 每跳重新归一和判定，首跳为原始地址、编号为 1，命中禁止范围抛 SSRF_HOP_DENIED、detail 带 {"hop","target"}；⑨ 跳数超过 max_redirects 抛 SSRF_REDIRECT_LIMIT 且链不再加长，下一跳与链上已有地址相同抛 SSRF_REDIRECT_LOOP；⑩ hops_for 按顺序返回完整链，targets 返回已建链的原始目标，未知目标 hops_for 返回空列表；⑪ 同一目标重复建链沿用原链，不得另起一条；⑫ snapshot 为 {"version","schemes","allow_hosts","deny_cidrs","max_redirects","targets","chains","bindings","stats"}，restore 遇缺失或类型不符抛 SSRF_SNAPSHOT_INVALID 且原状态一字不动。

两处容易漏的判定单独说清：域名解析在判定与请求之间发生变化时，按判定时点绑定的结果拒绝，不得拿新的解析结果放行；跳转到相对地址时基于上一跳的最终地址解析，不得基于用户最初提交的地址解析。

硬约束：同一目标并发追加跳转时链长单调不回退、跳数上限要么看到追加前要么看到追加后，不能出现一条链被两个调用方同时认定未超限；判定用的解析结果必须与判定结果一起留在链上，snapshot 深拷贝后 restore 能还原白名单、拒绝网段、链、绑定与全部计数。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: ssrf_target_resolver
- typeName: SsrfTargetResolver
