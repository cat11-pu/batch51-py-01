# batch51-py-safety-c-26

## 题面

蜜罐台账这月被审计挑出两处硬伤：同一段扫描流量在报表里被拆成十几条独立来源，值班按来源封网段时误封了一整片办公出口；另一批交互载荷把归档盘写满，事后复盘只剩时间戳没有内容。范围是 gsb/batch51-py-safety-c-26 下的 honeypot_hit_ledger.py，类 HoneypotHitLedger，负责把蜜罐交互事件按来源指纹聚类、在时间窗内折叠重复命中，并对载荷归档做单条与总量双限。

公开接口：HoneypotHitLedger(*, window_seconds=60, max_entries=64, max_payload_bytes=256, max_total_payload=1024)；record_hit(source_ip, *, client="", path="/", at=0)；fingerprint_for(source_ip, *, client="", at=0)；cluster_by_fingerprint(*, window_start=None)；dedupe_window(at)；archive_payload(fingerprint, payload, *, at=0)；payload_for(fingerprint)；source_trail(source_ip)；entries()；lookup(fingerprint)；snapshot()；restore(state)；stats()；reset()。拒绝时抛 HoneypotError(code, detail)。

要修的行为：①指纹由来源网段、客户端特征与请求节奏三段用竖线拼接：IPv4 取前三段，其他来源取小写原值；客户端去首尾空白后转小写，空值记 anon；节奏为 at 向下取整到 window_seconds 的整数倍。②首个命中建条目，hits 为 1、folded 为 False，first_seen 与 last_seen 都等于 at，path 记本次路径；同指纹再命中只把 hits 加一并刷新 last_seen 与 path，folded 为 True，不得新增条目。③同一网段不同来源地址、同客户端同窗口要归入同一指纹，条目的来源清单要去重升序。④跨窗口的命中另起条目，窗口起点必须是 window_seconds 的整数倍。⑤cluster_by_fingerprint 按指纹升序返回，可传 window_start 只看一个窗口，每条给出指纹、网段、客户端、窗口起点、来源与命中数。⑥dedupe_window 汇总该窗口的条目数、命中总数与被折叠掉的重复数，空窗口各项为 0。⑦载荷不超过单条上限时整份存储，digest 取 sha256 十六进制，payload_for 返回最近一次整份存储的内容、没有则为 None；超过单条上限只留摘要，stored_bytes 记 0、truncated 为 True，这种情况不计入溢出。⑧累计存储会突破 max_total_payload 的载荷只留摘要，归档只追加不覆盖、已存内容不回滚，payload_overflow 递增。⑨来源不是非空字符串、at 不是非负整数抛 HONEY_INVALID_HIT；未登记指纹归档抛 HONEY_UNKNOWN_FINGERPRINT；条目数达到 max_entries 后新指纹抛 HONEY_CAPACITY_EXCEEDED，而已有指纹的折叠不受影响。⑩同一来源更换客户端特征后按新指纹建条目，但要保留它与原条目的先后关联，source_trail 按来源串出这条链路。⑪窗口跨越重启时去重状态要延续，恢复后同一批命中不得被重新计成新条目。⑫快照返回 version、window_seconds、records、archives、stats 五项且为深拷贝，恢复后条目、归档与计数原样往返，结构不符抛 HONEY_SNAPSHOT_INVALID 且当前状态一字不动；stats 返回 hits、records、sources、folded、payloads、payload_overflow、restores。

硬约束：多线程同时 record_hit 时同指纹的命中数不能丢，单次折叠必须原子完成；载荷总量是硬顶，任何归档顺序都不能突破；恢复后的去重窗口与计数要和中断前一致。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: honeypot_hit_ledger
- typeName: HoneypotHitLedger
- file: honeypot_hit_ledger.py
