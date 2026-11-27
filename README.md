# batch51-py-game-b-19

## 题面

竞技场里换招总在原地打转：角色砍到第三段又从头起手，跑动追击时明明是直线却挑到转身帧，动作之间的过渡还会在一帧里抖两次，同一条查询在两次点击之间给出的候选也不同，连招衔接跟着漂。定位在动作匹配检索这一层：候选帧只按姿态距离排序，未来轨迹代价没算对，代价相同时顺序不稳定，索引增量更新后被删片段的向量还留在表里。请修 `gsb/batch51-py-game-b-19` 的 `motion_matching_index.py`，类 `MotionMatchingIndex` 把动画片段的姿态与未来轨迹编码成特征向量，按当前角色状态检索代价最低的候选帧，拒绝统一抛 `MotionError(code, detail)`。

公开接口：`MotionMatchingIndex(*, pose_weight=1.0, trajectory_weight=1.0, exclusion_window=2)`；`add_clip(clip_id, frames)`；`remove_clip(clip_id)`；`build_index()`；`query(state, *, limit=8)`；`set_weights(pose_weight, trajectory_weight)`；`commit_choice(clip_id, frame_index)`；`current_choice()`；`index_version()`；`stats()`；`snapshot()`；`restore(state)`。

要修的行为：①`add_clip` 的帧表不得为空，否则报 `MOTION_EMPTY_CLIP`；片段 ID 为空或帧缺字段报 `MOTION_INVALID_CLIP`；`time_ms` 必须严格递增、特征必须有限，否则报 `MOTION_INVALID_FRAMES`；重复片段报 `MOTION_DUPLICATE_CLIP`。②所有片段的姿态维度、轨迹维度与轨迹采样点数必须一致，否则报 `MOTION_DIM_MISMATCH`；查询状态维度不符同样报这个码。③代价为姿态欧氏距离乘 `pose_weight` 加轨迹逐点距离均值乘 `trajectory_weight`，保留六位小数，轨迹按平均而不是求和，样本数不同的片段不能互相比较。④检索结果按代价升序，同代价按片段 ID 再按帧序号升序，候选里不得出现重复的片段与帧组合；`limit` 必须为正整数，否则报 `MOTION_INVALID_LIMIT`。⑤索引未构建或有增删改动时查询报 `MOTION_INDEX_NOT_BUILT`；未改动的重复构建直接复用，版本号不变。⑥`set_weights` 任一权重为负或两者同时为零报 `MOTION_INVALID_WEIGHTS`，权重变化要让索引失效。⑦`commit_choice` 只接受已构建索引里存在的帧，否则报 `MOTION_UNKNOWN_FRAME`，提交后记录当前播放的片段与帧。⑧当前片段正在播放的帧及其后继 `exclusion_window` 帧要排除，避免在原地反复重启同一段动作。⑨轨迹代价按时间等距重采样后逐点比较，采样间隔随角色速度变化，不能固定采样点个数。⑩`remove_clip` 删除不存在的片段报 `MOTION_UNKNOWN_CLIP`，返回移除的帧数并把索引置脏；被删片段的向量不得残留参与检索。⑪快照含 `version`、`clips`、`pose_weight`、`trajectory_weight`、`exclusion_window`、`index_version`、`dirty`、`current`、`stats` 且为深拷贝，结构不符报 `MOTION_SNAPSHOT_INVALID` 且现有状态不变。⑫`stats()` 至少含 `clips`、`frames`、`builds`、`reused`、`queries`、`commits`、`removals`、`rejections`，其中 `queries` 只统计成功返回的检索，`commits` 只统计成功提交，被拒请求计入 `rejections`。

硬约束：索引构建与查询可并发，查询结果要么来自完整的旧版本，要么来自完整的新版本，`QueryResult.index_version` 必须与实际代价口径一致；同一状态重复查询结果逐字段一致；索引版本变化后旧查询结果不得被当作新版本返回。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发查询与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: motion_matching_index
- typeName: MotionMatchingIndex
