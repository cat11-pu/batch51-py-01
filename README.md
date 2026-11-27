# batch51-py-safety-c-24

## 题面

资产测绘组这周的复测结果对不上：同一批站点，A 同学报“主机头可注入、缓存可污染”，B 同学在同一地址上什么都没测出来；回看执行记录才发现，一个人只发了绝对地址一种变体，另一个人把大小写和端口变体重复发了三遍，还把 8443 的结果并到了 443 上；更要命的是，某个站点只在 404 页面上把主机头回显出来，也被记成了和业务页同一档的风险，工单直接升级到了业务方。复测计划每次靠人手工拼，同一批目标两次跑出来的变体集合都不一样。范围是 gsb/batch51-py-safety-c-24 下的 host_header_probe_planner.py，类 HostHeaderProbePlanner，负责按目标生成主机头变体、对观测结果定级，并判断缓存键是否把主机头算了进去。

公开接口：HostHeaderProbePlanner(*, per_target_limit=10)；add_target(target_id, *, host, scheme="https", ports=(443,))；remove_target(target_id)；plan_probes(target_id)；variants_for(target_id)；dedupe(target_id, probes)；classify_reflection(observation)；detect_cache_key(headers)；describe_target(target_id)；list_targets()；snapshot()；restore(state)；stats()；reset()。plan_probes 与 dedupe 返回 Probe 元组，Probe 字段为 target_id、variant、host_header、port。拒绝时抛 HostError(code, detail)。

要修的行为：① target_id 重复抛 HOST_DUPLICATE_TARGET；host 必须是不带 scheme、端口与路径的主机名，非法抛 HOST_INVALID_HOST，登记时统一转小写；② scheme 只取 http 与 https，端口必须是 1 到 65535 的整数且至少给一个，否则抛 HOST_INVALID_PORT；③ 变体按 plain、case、trailing-dot、port、absolute、duplicate、prefixed 的顺序生成，case 与 plain 规范化后同值，按去重规则被丢弃；④ 去重键是端口加规范化后的主机头值，规范化指去掉首尾空白、把连续空白压成一个空格、转小写，重复时保留首次出现的那条；⑤ 单目标探测总量受 per_target_limit 约束，超出部分不生成并计入 suppressed，add_target 返回实际生成的探测条数；⑥ 未知目标上调用 plan_probes、variants_for、dedupe 一律抛 HOST_UNKNOWN_TARGET，remove_target 返回是否真的移除；⑦ detect_cache_key 只在 Vary 里出现 host 令牌、或 X-Cache-Key 的值里含 host 时为 True，其余为 False，头部名不区分大小写；⑧ 只在错误页回显主机头时记低风险，不得与业务页回显同级；⑨ 业务页正文回显记中风险，正文回显且缓存键含主机头记高风险；⑩ 跳转地址回显记中风险，channel 记为 redirect，正文与跳转同时回显时优先按跳转归类；⑪ 同一目标不同端口的探测结果分别记录，去重不得跨端口合并；⑫ classify_reflection 返回 risk、channel、cache_key 三个字段，没有任何回显时 channel 为 none、risk 为 none。

describe_target 返回 target_id、host、scheme、ports、planned 五个字段，ports 按登记顺序以元组给出，planned 是当前实际生成的探测条数，list_targets 按登记顺序返回目标标识。stats 返回 targets、planned、suppressed、classifications、restores 五个计数；reset 清计数并保留目标登记与限额。

硬约束：同一实例被多个线程同时建目标、删目标与规划时，单次规划只能看到一个完整的目标定义，计数不得丢；快照必须深拷贝，restore 后目标、主机、端口、限额与计数原样往返，结构不符抛 HOST_SNAPSHOT_INVALID 且原状态一字不动；单目标探测总量是硬顶，任何端口组合与去重路径都不能突破。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: host_header_probe_planner
- typeName: HostHeaderProbePlanner
- file: host_header_probe_planner.py
