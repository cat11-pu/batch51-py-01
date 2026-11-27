# batch51-py-game-c-03

## 题面

直播转播车的值班同事先报的是导播台时间轴上一段三分钟的静止画面完全没有被标出来，回放时才发现那其实是源端掉了信号、机位冻结在最后一帧；接着是另一路，零点前后整段黑场没进报告，播控以为那段素材丢了。反过来的误报也麻烦，夜景里缓慢压暗的镜头被整段标成冻结，剪辑照着一刀切下去，画面直接跳到黑。

范围收到帧序列检测这一层，代码在 gsb/batch51-py-game-c-03 的 freeze_frame_detector.py，类 FreezeFrameDetector，按流比对相邻帧指纹与亮度，输出冻结区间和黑场区间，并给出置信度。

公开接口：FreezeFrameDetector(*, min_freeze_ms=200, min_black_ms=300, black_luma=0.08, max_ranges=32)；feed(stream, *, pts_ms, fingerprint, luma, epoch=1)；flush(stream)；ranges(stream=None)；open_range(stream)；confidence_of(stream, start_ms, kind="freeze")；set_threshold(stream=None, *, min_freeze_ms=None, min_black_ms=None, black_luma=None)；reset_stream(stream)；streams()；snapshot()；restore(state)；stats()。拒绝时抛 FreezeError(code, detail)。FrameRange 记录 stream、kind、start_ms、end_ms、frames、confidence、overlap。

故障与边界：

一、stream 去掉首尾空白后为空、pts_ms 不是非负整数、luma 不在 0 到 1 之间、fingerprint 不是非负整数、epoch 小于 1，一律 FREEZE_INVALID；被拒的一帧不进入任何计数。

二、同一条流同一 epoch 内 pts_ms 必须严格递增，相等或回退报 FREEZE_PTS_NON_MONOTONIC。

三、连续相同指纹构成冻结候选，区间起点是该段第一帧的 pts_ms，终点是该段最后一帧的 pts_ms，帧数是段内帧数；时长不足 min_freeze_ms 的候选整段丢弃并计入 discarded，不产生区间。

四、亮度不大于 black_luma 的帧构成黑场候选，起点、终点、帧数与丢弃规则同冻结，时长门槛换成 min_black_ms。

五、fingerprint 只做相等比较：相邻两帧指纹不同就不属于同一段，没有相似度、距离或容差这类判定。

六、候选区间在指纹变化、亮度回到阈值以上或 flush 时收口；flush 用该段最后一帧的 pts_ms 收口，返回本次收口产生的区间元组并清空比较窗口（last_pts 保留），此后 pts_ms 仍需大于它。

七、feed 与 flush 都返回本次收口的区间元组（通常是空元组），ranges 返回全部已收口区间组成的元组，带 stream 时只返回该流的；区间按 start_ms 升序排列，start_ms 相同按 kind 字典序。

八、confidence 按 min(1.0, 时长 / (2 乘 时长门槛)) 计算并写进区间；confidence_of 按 stream、start_ms 与 kind 查找，找不到报 FREEZE_RANGE_UNKNOWN。

九、set_threshold 带 stream 时只改该流，不带 stream 时改全局默认（没有单独设置过的流也跟着变），返回修改前生效的 min_freeze_ms、min_black_ms、black_luma 三项；门槛为负或 black_luma 越界报 FREEZE_INVALID，未知流报 FREEZE_UNKNOWN_STREAM。

十、已收口区间总数超过 max_ranges 时淘汰最旧的区间并计入 evicted，冻结与黑场共用这一个上限。

十一、reset_stream 清掉该流的所有区间与候选状态并返回移除的区间条数，流本身保留；streams 返回按字典序排列的流名元组；未知流报 FREEZE_UNKNOWN_STREAM。

十二、open_range 返回该流当前候选的 freeze_start、freeze_frames、black_start、black_frames、last_pts，没有候选时起点为 None、帧数为 0；未知流返回 None。

十三、stats 固定返回 streams、frames、freeze_ranges、black_ranges、discarded、evicted、resets 七个键；streams 是当前流数，其余都是累计值，其中 freeze_ranges 与 black_ranges 累计产生过的区间条数，淘汰与重置都不回退这两个数。

硬约束：黑场与冻结可以同时成立，两种区间都要输出，overlap 标出该区间是否与另一种区间有交叠。同一条流的帧必须按到达顺序处理，多路流并发 feed 互不影响，计数器不得丢更新。epoch 变化表示该路重新接入，比较窗口要从头开始，中断的空档不能算进区间时长。快照带走全部已收口区间、各流候选状态与计数器，恢复后继续 feed 得到的区间要与中断前衔接；快照结构损坏或字段缺失报 FREEZE_SNAPSHOT_INVALID，原状态一字不动。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: freeze_frame_detector
- typeName: FreezeFrameDetector
