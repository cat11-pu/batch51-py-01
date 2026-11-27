# batch51-py-game-c-11

## 题面

剪辑台的客户这个月连着退片：一段 60 秒素材按 0.5 倍慢放导出后只剩 31 秒，抽帧比对发现中段多出一截重复画面；从 1 倍切到 4 倍的转场处，监听里爆出一声撕裂般的爆音和咔哒；带解说词的片子变速后，人声与口型差出半秒，剪辑师只能手工逐帧推。范围是 gsb/batch51-py-game-c-11 的 speed_ramp_planner.py，类 SpeedRampPlanner，负责按输出时间轴上的速度关键帧规划源时间映射、音频拉伸分段与帧预算。

公开接口：SpeedRampPlanner(*, frame_rate=30, max_speed=8.0, max_keyframes=32, max_accel=0.5, max_output_frames=100000)；set_source_duration(frames)；set_keyframes(keyframes)；keyframes()；speed_at(output_frame)；map_time(output_frame)；unmap_time(source_frame)；output_frames()；frame_budget()；audio_segments()；validate()；stats()；snapshot()；restore(state)；reset()。拒绝一律抛 SpeedRampError(code, detail)。

要修的行为：

① 关键帧是（输出帧号，速度）二元组，必须严格递增、首帧为 0、速度在 0 到 max_speed 之间；为空、乱序、重复帧号、速度为负或超上限都按 SPEED_RAMP_INVALID 拒绝，keyframes() 升序返回 SpeedKeyframe。

② 关键帧个数超过 max_keyframes 抛 SPEED_RAMP_LIMIT，整批拒绝，先前生效的计划保持不变。

③ speed_at 取不大于该帧号的最后一个关键帧速度，最后一段之后沿用最后一个速度；帧号为负抛 SPEED_RAMP_INVALID。

④ map_time 返回该输出帧对应的源帧号并向下取整，段内按速度线性推进，结果单调不减。

⑤ unmap_time 返回第一个映射到不小于给定源帧号的输出帧，与 map_time 在帧级互为逆；尾部速度为零永远到不了时抛 SPEED_RAMP_UNREACHABLE。

⑥ 速度为零的暂停段不推进源时间，但输出仍要占帧，必须按静止帧填充而不是跳过或压缩。

⑦ 总时长要按帧号回算，不允许把每帧增量累加后直接当结果，长片段与分段累加必须一致到帧；跨段边界的那一帧归后一段，不能重复计入两段；output_frames 返回映射首次达到源时长的输出帧号。

⑧ 相邻关键帧速度跳变超过 max_accel 时，validate() 返回 RampIssue("ACCEL_LIMIT", at_frame)，frame_budget() 直接抛 SPEED_RAMP_ACCEL_LIMIT，不能生成瞬间跳变的曲线；set_keyframes 只做顺序与范围校验，不因加速度拒绝。

⑨ frame_budget 返回 output_frames、source_frames、freeze_frames、budget 四项，budget 为 max_output_frames，freeze_frames 是预算内速度为零的输出帧数；需要超过 max_output_frames 时抛 SPEED_RAMP_BUDGET_EXCEEDED，未设源时长抛 SPEED_RAMP_STATE。

⑩ audio_segments 按输出区间切分并与视频段边界对齐，给出 index、output_start、output_frames、source_start、source_frames、ratio，source_frames 是该段消耗的源帧数，ratio 为输出帧数除以源帧数；跨段边界的拉伸段要按重叠窗口交叉淡化，fade_frames 记录窗口长度，硬切会产生爆音。

⑪ stats 固定给出 keyframes、intervals、max_speed、min_speed，intervals 等于关键帧个数，无关键帧时后两项为 0.0；stats 只读，不改计划与计数。

⑫ snapshot 含 version、frame_rate、max_speed、max_keyframes、max_accel、max_output_frames、source_frames、keyframes、plans 九项且为深拷贝，plans 记录 frame_budget 成功调用的次数；restore 能恢复到新实例继续映射，非法结构抛 SPEED_RAMP_SNAPSHOT_INVALID 且现有状态一字不动；reset 清空关键帧、源时长与计数。

硬约束：同一实例的 set_keyframes 与 map_time 会被导出线程和预览线程同时调用，关键帧、源时长与计数不得读到半写状态；被拒的调用不得改动任何已生效的计划；关键帧个数与输出帧预算都是硬上限。

验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: speed_ramp_planner
- typeName: SpeedRampPlanner
