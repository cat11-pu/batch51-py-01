# batch51-py-game-a-25

## 题面

世界 Boss 与采集点改版后，玩家反馈两种极端：同一个 Boss 刷到第五只收益就断崖式下跌，换个地图重新开一只又回到满收益；反过来，队伍里两个人已经打了很多只，第三个人刚进队第一只就吃到全队最差的系数；维护重启之后递减状态全部清零，一个晚上被同一批号刷了十几轮。范围是 `gsb/batch51-py-game-a-25` 的 `diminishing_returns_ledger.py`，类 `DiminishingReturnsLedger` 负责按目标模板与队伍维护递减桶，参数非法或状态不符抛 `DiminishingError(code, detail)`。

公开接口：`DiminishingReturnsLedger(*, floor=0.25, step=0.15, window=600, cycle=86400, max_buckets=512, max_history=64)`；`record(event_id, *, template, player, at, instance=None, party=None)`；`multiplier(template, player, *, at)`；`bucket_state(template, player, *, at)`；`reset_cycle(*, at)`；`share_with_party(player, party)`；`party_of(player)`；`leave_party(player)`；`prune(*, at)`；`snapshot()`；`restore(state)`；`stats()`。

需要落地的行为：①没有任何记录时系数为满值 1.0，同一个桶每多一条窗口内事件按 `step` 递减一次，不低于 `floor`，结果四舍五入保留三位小数；②系数只统计衰减窗口 `(at - window, at]` 内的事件，窗口之外的事件不再参与；③同一 `event_id` 重复上报只计一次，重复调用返回首笔的 `count` 与 `multiplier` 并把 `duplicate` 置真；④空 `event_id`、空模板、空玩家或负时间戳报 `DIM_INVALID_REQUEST`，早于桶所属周期的时间戳报 `DIM_CYCLE_MISMATCH`；⑤`bucket_state` 返回 `template`、`player`、`count`、`multiplier`、`cycle`、`party` 六个字段，未产生过的桶按空桶返回；⑥队伍成员共享同一个递减桶，取成员集合里最严格的系数，也就是计数最大的那个；⑦队伍成员中途加入时不继承入队前的历史计数，离队后保留自己的个人桶；⑧周期重置之后首个事件的系数要回到满值，不能沿用上一周期的衰减状态；⑨同一目标的不同刷新实例共享递减桶，按目标模板而不是实例编号计数；⑩`share_with_party` 返回加入后的成员数，`party_of` 对未知玩家返回 `None`，`leave_party` 对未知玩家返回 `False`；⑪桶数量受 `max_buckets` 硬顶，超出时淘汰最久未使用的桶并在 `stats` 的 `evicted` 里累计；`prune` 清理窗口外事件并返回清理条数；⑫快照含 `version`、`config`、`buckets`、`events`、`parties`、`counters` 六项且为深拷贝，结构不符的恢复报 `DIM_SNAPSHOT_INVALID` 且原状态一字不动。

硬约束：结算在线程池里并行执行，同一个桶的 `record` 并发时只能按到达顺序累加，计数与事件历史不允许丢条；进程重启后从快照恢复桶、窗口内事件与队伍关系，重复上报仍然幂等；桶数量与每个桶保留的历史事件数都有上限，长时间运行不能让内存随在线时长增长。

验收：`python3 -m pytest -q tests` 的 15 条用例必须全部通过；测试不得修改、不得跳过、不得按固定输入写死；并发调用与进程重启恢复请自行构造场景验证；接口签名、错误码与幂等语义以题面为准，不得自行增删；越界输入一律在写入前拒绝，不能落库后再回滚；只做本地实现，交付源码、测试记录与一份改动说明，改动不要提交到上游仓库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: diminishing_returns_ledger
- typeName: DiminishingReturnsLedger
