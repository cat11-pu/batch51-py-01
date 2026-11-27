# batch51-py-game-c-05

## 题面

乐队这周返工了三次同一段主唱：第一版从第二次 take 里挑了副歌，第二版把桥段换回第一版，第三版听起来副歌开头有一声极轻的咔哒，监棚说拼接位置差了一个样本。还有人把一条临时车道静音之后，成品轨那一整段直接变成空白，而不是露出下面那条；批量把五条 take 摆进时间线后想整体撤回，撤销键按一次只退了一条，剩下的位置全乱了。

范围收到多轨补录拼接这一层，代码在 gsb/batch51-py-game-c-05 的 take_comping_ledger.py，类 TakeCompingLedger，管理同一段录音的多条 take 车道，按区域拼成成品轨，重叠时按优先级取上层，并在边界生成交叉淡化。

公开接口：TakeCompingLedger(*, max_takes=8, max_regions=32, crossfade_samples=64)；add_take(take_id, *, length_samples, gain_db=0.0, muted=False)；place_region(take_id, *, start, end, at, priority=0)；place_batch(*, placements)；set_priority(region_id, priority)；set_muted(take_id, muted)；remove_region(region_id)；resolve_overlaps(*, start, end)；bounce(*, start, end)；undo()；snapshot()；restore(state)；stats()。拒绝时抛 TakeError(code, detail)。TakeInfo 记 take_id、length_samples、gain_db、muted；RegionInfo 记 region_id、take_id、start、end、at、priority；Segment 记 take_id、start_sample、end_sample、gain_db、fade_in、fade_out；BounceResult 记 segments、total_samples、silent_samples。

故障与边界：

一、take_id 去空白后为空、length_samples 不是正整数、gain_db 不在 -60 到 24 之间报 TAKE_INVALID；重名报 TAKE_EXISTS；超过 max_takes 报 TAKE_CAPACITY。

二、区域按样本整数计：start 为负、end 超过素材长度、start 不小于 end、at 为负、priority 超出 -1000 到 1000 报 TAKE_REGION_INVALID；未知 take 报 TAKE_UNKNOWN；超过 max_regions 报 TAKE_CAPACITY；被拒的摆放不落记录也不消耗 region_id。

三、region_id 从 1 起单调递增、永不复用，place_region 返回完整 RegionInfo。

四、bounce 在 start 到 end 的每个样本上，从可听区域里取 priority 最大者为胜者；priority 相同取 region_id 更大的。

五、连续同一胜者的样本合成一个 Segment，start_sample 与 end_sample 左闭右开；没有胜者的样本计入 silent_samples，total_samples 等于 end 减 start。

六、相邻两段胜者不同时接缝两侧各承担一半淡化，长度取 crossfade_samples 与两侧各自长度一半三者中的最小值，fade_in、fade_out 如实反映；段与段首尾相接，不留缝隙也不重叠。

七、静音车道的区域不参与胜负判定但区域仍留在工程里，set_muted 切换立即影响下一次 bounce，未知 take 报 TAKE_UNKNOWN。

八、resolve_overlaps 返回与 bounce 相同的 Segment 元组但不给 total_samples 与 silent_samples；start 不小于 end 或为负报 TAKE_INVALID。

九、set_priority 立即影响下一次 bounce，未知 region 报 TAKE_UNKNOWN；remove_region 返回被删的 RegionInfo，未知 region 报 TAKE_UNKNOWN。

十、place_batch 每条是含 take_id、start、end、at、priority 的映射，一次校验全部条目，任何一条不合法整批拒绝、一条都不落库；全部合法时返回按摆放顺序的 RegionInfo 元组，并作为一次操作进入撤销栈。

十一、undo 只回退最近一次区域变更：place_region 回退一条返回 1，remove_region 回退一条返回 1，place_batch 整体回退返回条数；set_priority 与 set_muted 不进撤销栈；没有可回退时报 TAKE_NOTHING_TO_UNDO。

十二、snapshot 返回 version、next_region、takes、regions、undo、stats 六个键，是深拷贝；restore 对缺键、类型不对或 version 不认识的快照抛 TAKE_SNAPSHOT_INVALID，原状态一字不动，恢复后撤销栈仍可继续用。

十三、stats 固定返回 takes、regions、audible_regions、placed、removed、bounces、undone 七个键；前三项是当前值，其中 audible_regions 是当前未静音 take 所占区域数，后四项是累计值。

硬约束：拼接按整数样本计算，不允许浮点累加，任何一段的 end_sample 必须等于下一段的 start_sample；静音与优先级变更不影响已生成的 BounceResult；快照恢复后 undo 接着快照进度继续；并发摆放串行且 region_id 不重号。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: take_comping_ledger
- typeName: TakeCompingLedger
