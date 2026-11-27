# batch51-py-game-c-10

## 题面

播客批量剪辑上线后，三位主播的节目都被裁出了新毛病：一口气说完的长句中间那些换气点被逐个剪掉，剪完听着像在抢拍；某个只有 120 毫秒的短片段被加上 200 毫秒淡出，导出时直接报错；还有一期有六个剪切点，剪完之后字幕从第二段开始越错越靠后，到片尾差了近两秒。剪辑师说他们手上有一份静音阈值配置，可同一段录音连着分析两次给出的区间个数都不一样，怀疑阈值附近的抖动被切成了碎段。

请在 `gsb/batch51-py-game-c-10` 的 `silence_cut_planner.py` 里补完 `SilenceCutPlanner`：从逐帧能量与过零率检出静音区间，生成裁剪清单，并在剪切点安排淡入淡出与最小保留时长。拒绝一律抛 `SilenceError(code, detail)`。

公开接口：`SilenceCutPlanner(*, sample_rate=48000, frame_ms=20, silence_db=-45.0, zcr_max=0.35, min_silence_ms=300, min_keep_ms=200, fade_ms=10, max_ranges=1024, max_frames=100000)`；`analyze(frames, *, sample_rate=None)`；`silence_ranges()`；`voiced_ranges()`；`merge_gaps(min_keep_ms=None)`；`plan_cuts(*, pad_lead_ms=0, pad_tail_ms=0)`；`apply_padding(pad_lead_ms, pad_tail_ms)`；`cuts()`；`preview()`；`snapshot()`；`restore(state)`；`stats()`。`FrameRange` 记 `start_ms`、`end_ms`；`Segment` 记 `start_ms`、`end_ms`、`fade_in_ms`、`fade_out_ms`；`CutPlan` 记 `kept`、`cuts`、`removed_ms`。

要修的行为：

① 采样率、帧长、最短静音、最短保留、淡化长度、区间上限与总帧上限都必须是正整数，`silence_db` 必须是数值，`zcr_max` 落在 0 到 1，违规抛 `SIL_INVALID_ARG`。

② `analyze` 的每一帧是一对（RMS 分贝、过零率）：分贝为数值，过零率落在 0 到 1，违规抛 `SIL_INVALID_FRAME`；空序列抛 `SIL_EMPTY_BUFFER`；传入采样率与构造值不一致抛 `SIL_SAMPLE_RATE`。

③ 第 k 帧覆盖从 k 乘 `frame_ms` 到 (k+1) 乘 `frame_ms`；分贝不高于 `silence_db` 且过零率不高于 `zcr_max` 的帧判为静音，能量虽低但过零率高（气声、底噪）不算静音。

④ 连续静音帧合成一个区间，端点按帧边界取整、单位毫秒；短于 `min_silence_ms` 的区间直接丢弃，阈值附近的抖动不能切成碎段。

⑤ 保留段是静音区间相对整个已分析窗口的补集，`silence_ranges` 与 `voiced_ranges` 都按时间升序、互不重叠。

⑥ `merge_gaps` 把被短于阈值的有声段隔开的两条静音区间合并成一条并返回合并条数，阈值缺省取 `min_keep_ms`，负数抛 `SIL_INVALID_ARG`，已经合并过的结果不重复计入。

⑦ `plan_cuts` 用当前静音区间生成剪切清单与保留段，保留段按时间升序、互不重叠，`removed_ms` 等于被剪掉的总毫秒数；同一次规划之后 `cuts()` 返回实际使用的剪切区间。

⑧ 留白：剪切区间前后各加 `pad_lead_ms` 与 `pad_tail_ms`，越出 0 到总时长的部分截掉；两条加过留白的剪切区间重叠时，在它们之间的有声段中点切开，不允许重叠，也不允许为了避让把两段合并。

⑨ 淡化：保留段紧邻剪切点的一端取 `fade_ms`，另一端为 0；淡化长度不能超过被保留片段的长度，极短片段要缩短淡化而不是越界。

⑩ `preview` 给出源总时长、输出总时长、保留段与剪切区间；裁剪后时间戳要整体前移并保持单调，多个剪切点之间的偏移要累加而不是各自从零重置。

⑪ 帧数受 `max_frames` 硬顶、区间数受 `max_ranges` 硬顶，越顶抛 `SIL_CAPACITY` 且这次分析不生效，本次提交的帧一帧都不留。

硬约束：`analyze`、`merge_gaps` 与 `plan_cuts` 会被分析线程和预览线程同时调用，帧、区间、合并状态与计数不得互相踩，八路并发喂入同一批帧后总帧数等于各次之和，区间不重复也不丢；一次分析要么全生效要么全不生效。`snapshot` 含 `version`、`sample_rate`、`frame_ms`、`frames`、`ranges`、`stats` 六项且为深拷贝，`restore` 能恢复到新实例继续分析与出清单，非法结构抛 `SIL_SNAPSHOT_INVALID` 且现有状态一字不动。帧数与区间数是硬上限，长录音的内存不随分析时长无界增长。`stats()` 固定返回 `frames`、`duration_ms`、`silences`、`cuts`、`kept`、`merged`、`plans`、`rejected`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发分析与快照恢复自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: silence_cut_planner
- typeName: SilenceCutPlanner
