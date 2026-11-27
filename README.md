# batch51-py-safety-r-03

## 题面

图片代理与 webhook 派发上线第一周，内网监控就抓到有人从公网侧把本机管理页整页读走。回放请求时三种写法全都过了：把 127.0.0.1 写成十进制整数 2130706433 的、写成 0x7f.1 的、还有前导零的 0177.0.0.1。另一条更麻烦，白名单里的域名第一次解析出公网地址、判定也过了，真正建连那一刻解析结果换成了 10 网段，请求照样连了出去；值班还翻到跳转链只判了最后一跳，中间某跳落到云元数据地址也一路跟完。范围是 gsb/batch51-py-safety-r-03 的 ssrf_rebind_filter.py，类 SsrfRebindFilter，负责出站地址的归一、范围判定、解析复核与跳转链审计。

公开接口：SsrfRebindFilter(*, schemes=("http","https"), allow_hosts=(), allow_ports=(80,443), max_redirects=5, max_hops=8, resolver=None, allowed_cidrs=())；normalize(raw)；classify(address)；bind_resolution(host, addresses, *, now=None)；decide(raw, *, now=None)；authorize(target, *, now=None)；follow_redirect(decision, location, *, now=None)；allow_host(host)；allowed_hosts()；audit_log()；snapshot()；restore(state)；stats()。resolver 形如 resolver(host) -> 地址元组；目标地址一律用字符串表示，IPv4 尽量写成点分十进制。

要修的行为：① 归一阶段做四件事：scheme 与 host 小写、丢弃 userinfo 段、按 RFC 3986 折叠点段、空路径补成 /、默认端口补全；数字写法（十进制整数、0x 十六进制、前导零八进制）先还原成点分十进制再判；② 缺主机、端口不在 1 到 65535、整体不像 URL，normalize 抛 SsrfError 且码为 SSRF_URL_INVALID；scheme 不在允许列表抛 SSRF_SCHEME_REJECTED；③ classify 返回 public、private、loopback、link_local、metadata、invalid 六种之一，元数据地址优先判成 metadata，带 zone id 或方括号的地址先剥壳再判；④ 判定顺序：形状与 scheme、主机白名单、端口、解析、地址范围；allow_hosts 非空时按精确主机比对，大小写不敏感、忽略末尾点、不做后缀通配，不匹配报 SSRF_HOST_NOT_ALLOWED；登记值在内部归一去重（小写、去末尾点），allowed_hosts() 按归一键返回元组；端口不在 allow_ports 报 SSRF_PORT_REJECTED；⑤ 解析：host 本身是 IP 字面量直接判，否则走 resolver，拿不到地址报 SSRF_UNRESOLVED；命中的地址只要落进 private、loopback、link_local 就报 SSRF_ADDRESS_DENIED，落进元数据地址报 SSRF_METADATA_DENIED，allowed_cidrs 里显式放行的网段除外；⑥ decide 与 follow_redirect 不抛网络类异常，一律折算成 verdict 为 deny 的决策并带上原因码，failed_hop 指向出问题的那一跳，形状层面失败的决策不追加跳记录，决策里的 target 保留归一后的 scheme、host、port、path 与 normalized；⑦ 每判定一个目标追加一条 HopRecord（index 从 0 起、含 url、addresses、verdict、reason），跳转逐跳复核；⑧ 跟随次数超过 max_redirects、或链长触到 max_hops，追加一条 verdict 为 deny、reason 为 SSRF_REDIRECT_LIMIT 的记录并把 failed_hop 指向它，不再放行；⑨ 审计每跳落一条，含 code、host、addresses、hop 与原因；⑩ stats 给出 allowed、denied、hops、redirects、restores 五项；⑪ 快照含 version、allow_hosts、bindings、audit、stats 五项，取出后与实例不共享可变结构，恢复要校验结构与类型，非法报 SSRF_SNAPSHOT_INVALID 且不动现有数据，成功计一次 restores。

另外三个现场要一并兜住：一是同一域名两次解析结果不同时，以连接瞬间的解析结果为准，即使命中缓存也要重新复核，缓存只能当判定时点的快照用；二是 IPv6 映射地址与 zone id 混写（例如 [::ffff:127.0.0.1%eth0]）要先还原成内层地址再判，不能因为带冒号或百分号就跳过；三是重定向到白名单域名、但该域名这次解析落到内网时，整条链判失败并把失败跳记在链上，而不是只把最后一跳判掉。

硬约束：解析复核与范围判定要在同一把锁内完成，绑定表更新与判定并发时只能读到完整的一份快照；快照恢复后白名单、绑定表、审计与计数必须自洽；跳转链长度与单次判定的跳数都受硬顶，超限即拒而不是截断后放行。验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 其他
- type: Bugfix
- module: ssrf_rebind_filter
- typeName: SsrfRebindFilter
