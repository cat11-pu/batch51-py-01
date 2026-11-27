# batch51-py-game-c-08

## 题面

点播转码农场把逐段质检接进流水线后，重编队列一夜之间涨了四倍：一段静态黑场过场被打了 0.12 分，其实肉眼与源片几乎一致；同一段因为调度重试被提交了两遍，预算被扣掉两格；更奇怪的是同一批分片在四台机器上汇总出的通过数对不上，运维怀疑汇总顺序会影响判定。报告里还冒出五个分片标着“已通过”，其实是预算用完之后直接放行的，下游一次都没重编，画质问题就这么漏到线上。

请在 `gsb/batch51-py-game-c-08` 的 `encode_quality_gate.py` 里补完 `EncodeQualityGate`：对每个编码分片算质量指标并与源画面比对，低于阈值标记重编，累计重编次数受预算约束。拒绝一律抛 `GateError(code, detail)`。

公开接口：`EncodeQualityGate(*, threshold=0.95, budget=8, max_segments=512, max_frames_per_segment=4096, workers=4)`；`set_threshold(value)`；`set_budget(value)`；`budget_left()`；`submit_segment(segment_id, *, decoded, source)`；`score(segment_id)`；`decide(segment_id)`；`evaluate_all(*, workers=None)`；`report()`；`segments()`；`segment_info(segment_id)`；`snapshot()`；`restore(state)`。`SegmentInfo` 记 `segment_id`、`frames`、`score`、`decision`、`evaluated`；提交的帧是 `(pts, 像素序列)` 对。

要修的行为：

① 阈值必须落在 0 到 1（含端点），非法抛 `QG_INVALID_THRESHOLD`；`set_threshold` 返回改动前的阈值。

② 预算必须是非负整数，非法抛 `QG_INVALID_BUDGET`；`set_budget` 返回改动前的预算，`budget_left` 返回当前剩余。

③ `segment_id` 去空白后不得为空，重名抛 `QG_SEGMENT_EXISTS`；已提交分片数受 `max_segments` 硬顶，越顶抛 `QG_CAPACITY`。

④ `decoded` 与 `source` 的帧数必须相等且不为零，否则抛 `QG_FRAME_COUNT`；单段帧数受 `max_frames_per_segment` 硬顶，越顶抛 `QG_CAPACITY`。

⑤ 每帧的 `pts` 是非负整数且段内不得重复（重复抛 `QG_DUPLICATE_PTS`）；像素必须是非空整数序列、取值 0 到 255、同一段内各帧长度一致，违规抛 `QG_INVALID_FRAME`；被拒的提交不占编号，也不计入提交数。

⑥ 指标按 `pts` 对齐后逐像素求平均绝对误差，`score` 等于 1 减去平均绝对误差除以 255，保留六位小数；短分片与长分片用同一口径，不做按段长的加权。

⑦ 源画面是纯色或纯黑、逐像素方差为零时结构项无定义，回退到亮度误差口径判定，不能直接判零分把过场打成最差。

⑧ `score` 与 `decide` 对未提交的分片抛 `QG_UNKNOWN_SEGMENT`；`score` 只读，不改变判定状态与预算。

⑨ `score` 不低于阈值判 `accept`；低于阈值且预算还有剩余时扣一格判 `reencode`；预算耗尽后剩余分片一律 `accept`，但报告里要保留未评估标记，不能伪装成通过。

⑩ 同一分片重复判定不得重复扣预算：已判定过的再次 `decide` 返回首次结果，预算与计数都不动。

⑪ `evaluate_all` 在线程池里并行评估全部分片，返回分片号到判定的完整映射，结果与逐条 `decide` 一致，也与线程完成顺序无关；重复调用不再扣预算。

⑫ 分片首尾的帧要按显示顺序对齐而不是解码顺序，带双向预测帧的段先按 `pts` 升序摆好再比较，错位会让指标虚低。

硬约束：`submit_segment`、`decide` 与 `evaluate_all` 会被质检线程和重编调度线程同时调用，提交、扣预算与认定必须串行且不重不漏；八路并发提交同一批分片后分片数等于互不相同条数，预算扣减总数等于判为 `reencode` 的条数。`snapshot` 含 `version`、`threshold`、`budget_left`、`segments`、`counters` 五项且为深拷贝，`restore` 能恢复到新实例继续判定，非法结构抛 `QG_SNAPSHOT_INVALID` 且现有状态一字不动。分片条数、单段帧数与重编预算都是硬上限，不允许先放行再回滚。`report()` 固定返回 `segments`、`accepted`、`reencode`、`unevaluated`、`budget_spent`、`budget_left`、`threshold`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发评估与快照恢复自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: encode_quality_gate
- typeName: EncodeQualityGate
