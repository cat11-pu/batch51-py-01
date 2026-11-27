# batch51-py-safety-b-07

## 题面

办公区投屏服务改名之后，同一网段里两台机器反复抢一个名字：一台刚宣告完就被另一台的记录顶掉，日志里明明记了冲突，控制台上仍显示可用；有人抓包发现探测还没走完的实例已经在回答查询，把尚未申领的名字当成自己的；更麻烦的是一次缓存刷新把同名字的打印服务一起清掉，用户端整片服务消失，只能重启终端，会议室换个地址整层楼的终端还要手动重连一遍。范围是 gsb/batch51-py-safety-b-07 的 mdns_conflict_guard.py，类 MdnsConflictGuard，负责探测、申领、观测、解析、防御与快照恢复，拒绝抛 MdnsError(code, detail)。

公开接口：MdnsConflictGuard(*, probe_count=3, probe_interval=250, max_records_per_interface=64)；register_instance(instance, *, name, service_type, port, iface, target=None, unique=True, now=None)、begin_probe(name, service_type, iface, now=None)、tick(now=None)、announce(name, service_type, iface, now=None)、observe(record, iface, now=None)、resolve(name, service_type, iface)，另有 probe_state、instance_record、defend、mark_cache_flush、take_flushed、records_for、release、stats、snapshot、restore。

故障与边界：①实例按 instance 登记，唯一记录以名称、服务类型、接口三元组定位，同三元组重复登记报 MDNS_NAME_TAKEN，unique=False 的共享记录允许多实例并存，records_for 与 resolve 都按 instance 升序返回元组，未登记返回空元组；②每个接口的记录条数超过 max_records_per_interface 报 MDNS_CAPACITY_EXCEEDED，port 小于 1 或名称为空报 MDNS_INVALID_INSTANCE；③begin_probe 从 probing 起步，remaining 等于 probe_count，next_probe_at 等于 now 加 probe_interval，同一三元组已有探测或已宣告报 MDNS_NAME_TAKEN；④tick 只在 now 到达 next_probe_at 时推进一次，未到期返回 0 且计数不变；每次推进 remaining 减一，减到 0 转 announced 并记 announced_at，next_probe_at 置空；⑤探测阶段收到针对同一名称的查询按尚未申领处理，不回防御应答，宣告完成后 defend 才返回 defend；⑥观测记录与本机同名同类型同接口且 target、port 完全一致返回 duplicate，不改名也不计冲突；⑦同接口同名同类型但 target 或 port 不同视为冲突，返回 conflict，conflicts 加一，实例名追加 -2 并回到 probing 重新计时；⑧冲突记录来自与本机不同的接口时不得触发改名，只当作无关缓存处理；⑨观测记录的名称、类型与本地登记都不匹配时按缓存刷新处理并返回 refreshed；⑩缓存刷新标志只作用于同名称同类型的记录，mark_cache_flush 返回被标记条数，take_flushed 返回记录元组并清掉标志，再次调用返回空；⑪release 清除三元组的状态与记录并计数，未知三元组返回 False；⑫announce 在 announced 状态刷新 announced_at 并返回 True，probing 状态返回 False 且不计数。

硬约束：两个线程同时对同一三元组 begin_probe 只能有一个进入探测，另一个报 MDNS_NAME_TAKEN，状态和计数不得写坏；快照固定 version、instances、states、flushed、stats 五键，深拷贝，restore 校验结构，缺键或类型不符报 MDNS_SNAPSHOT_INVALID 且原状态不动，恢复后剩余探测次数、下一次探测时刻与已宣告状态都要继续可用，重启不能把探测次数清零。stats 返回 probes、announced、conflicts、released、refreshed、flushed。

验收：python3 -m pytest -q tests 15 条全过；不改测试、不跳过、不按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- module: mdns_conflict_guard
- typeName: MdnsConflictGuard
- file: mdns_conflict_guard.py
