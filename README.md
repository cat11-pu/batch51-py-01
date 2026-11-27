# batch51-py-game-c-09

## 题面

竖屏频道上线第一周，剪辑师反馈了三类问题：人物走到画面左侧就只剩半张脸，构图明明已经贴边还要硬跟，导出后外侧留出一条黑边；双人对谈时镜头在两人之间来回跳，三秒里切了七次，观感像手抖；还有人删掉一个关键帧想重排构图，结果删除点之后的窗口没有重新插值，播放时画面突然漂了一下。更早的版本里同一时刻还能插进两个关键帧，后写的悄悄盖掉先写的，谁也不知道哪一帧真的生效。

请在 `gsb/batch51-py-game-c-09` 的 `smart_reframe_tracker.py` 里补完 `SmartReframeTracker`：在原始画幅里跟踪主体位置，生成随时间的裁剪窗口关键帧，让主体始终落在目标画幅的安全区内。拒绝一律抛 `ReframeError(code, detail)`。

公开接口：`SmartReframeTracker(*, aspect_num=9, aspect_den=16, max_keyframes=64, max_track=1024, max_step_px=64, max_accel_px=32)`；`set_source(width, height)`；`observe(timestamp_ms, subjects)`；`primary_at(timestamp_ms)`；`confidence_at(timestamp_ms)`；`add_keyframe(timestamp_ms, center_x)`；`remove_keyframe(timestamp_ms)`；`keyframes()`；`window_at(timestamp_ms)`；`render_plan(*, start_ms=0, end_ms=None, step_ms=40)`；`snapshot()`；`restore(state)`；`stats()`。`SourceInfo` 记 `width`、`height`、`window_width`；`TrackSample` 记 `timestamp_ms`、`subject_id`、`x`、`y`、`confidence`；`Keyframe` 记 `timestamp_ms`、`center_x`；`Window` 记 `timestamp_ms`、`x`、`width`、`center`。

要修的行为：

① 源宽高必须是正整数，非法抛 `RF_INVALID_SOURCE`；源尺寸只能在开始时设置一次，重复设置相同尺寸幂等返回同一信息，换成不同尺寸抛 `RF_INVALID_SOURCE`。

② 窗口宽度等于源高乘 `aspect_num` 再除以 `aspect_den`，结果四舍五入；没有任何关键帧时窗口横向居中。

③ `observe` 的时间戳必须是非负整数，非法抛 `RF_INVALID_TIME`；与上一条相同抛 `RF_DUPLICATE_TIME`，比上一条更小抛 `RF_OUT_OF_ORDER`。

④ 每个主体项是（标识、`x`、`y`、权重）：标识去空白后非空，`x` 落在 0 到源宽减一、`y` 落在 0 到源高减一，权重为正数，违规抛 `RF_INVALID_SUBJECT`；被拒的观测不落样本，也不推进时间。

⑤ 同一时刻有多个主体时取权重最大者为主，权重相同取先出现的那个。

⑥ 视野里没有主体时保持上一次的主体位置，置信度每次减 0.25、最低到 0，丢失次数累加；重新看到主体后置信度回到 1.0。

⑦ 轨迹长度受 `max_track` 硬顶，超出后按时间均匀抽稀并保留首尾两条，丢弃条数计入 `dropped`。

⑧ `add_keyframe` 时间戳重复抛 `RF_DUPLICATE_TIME`，`center_x` 超出 0 到源宽抛 `RF_WINDOW_OUT_OF_BOUNDS`，条数受 `max_keyframes` 硬顶抛 `RF_KEYFRAME_LIMIT`；`remove_keyframe` 对不存在的时刻抛 `RF_UNKNOWN_KEYFRAME`，成功时返回被删的关键帧。

⑨ 关键帧之间按缓动插值，中点恰好落在两帧中心的中点；第一帧之前与最后一帧之后保持端点位置不动。

⑩ 主体靠近画幅边缘时窗口贴边停住而不是继续跟随，窗口左边界不得为负、右边界不得越过源宽减窗口宽，否则会裁出画面外的黑边。

⑪ 两个主体分居画面两侧、无法同时入镜时按权重选主，切换要满足最短停留时间，不允许每帧来回跳。

⑫ 关键帧删除后相邻两帧的插值要重新计算，不能沿用删除前算好的中间结果。

硬约束：`observe`、`add_keyframe` 与 `window_at` 会被跟踪线程和渲染线程同时调用，样本、关键帧与计数不得互相踩，八路并发观测后样本数等于被接受的条数之和；相邻渲染步之间的窗口位移受 `max_step_px` 约束，位移变化受 `max_accel_px` 约束，转折要平滑而不是硬切。`snapshot` 含 `version`、`source`、`samples`、`keyframes`、`stats` 五项且为深拷贝，`restore` 能恢复到新实例继续跟踪与出窗，非法结构抛 `RF_SNAPSHOT_INVALID` 且现有状态一字不动。轨迹长度与关键帧数量都是硬上限，不允许先存后删。`stats()` 固定返回 `samples`、`subjects`、`keyframes`、`lost`、`dropped`、`plans`、`rejected`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发观测与快照恢复自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: smart_reframe_tracker
- typeName: SmartReframeTracker
