# batch51-py-game-b-16

## 题面

夜战地图上线后，玩家贴在墙角时影子会横穿整个房间，紧邻的那面墙反倒一点阴影都没有，美术反复挪灯也没改善；同一盏灯在两次构建之间顶点顺序还会变，阴影边缘跟着抖。定位到二维阴影扇区构建这一段：遮挡线段的端点没有按相对灯位的角度稳定排序，相邻墙段各自生成扇区导致接缝叠色，扇区跨越零度时被拼成一整圈，顶点数量也没有上限。请修 `gsb/batch51-py-game-b-16` 的 `occluder_fan_builder.py`，类 `OccluderFanBuilder` 从遮挡线段集合为每盏灯构建阴影扇区，拒绝统一抛 `FanError(code, detail)`。

公开接口：`OccluderFanBuilder(*, merge_epsilon_deg=1e-6, vertex_budget=64, max_segments=256)`；`add_light(light_id, x, y, radius, *, facing_deg=None, cone_deg=None)`；`add_segment(seg_id, x1, y1, x2, y2)`；`remove_segment(seg_id)`；`set_vertex_budget(budget)`；`build_fan(light_id)`；`fan_vertices(light_id)`；`sectors(light_id)`；`coverage(light_id)`；`invalidate(light_id=None)`；`stats()`；`snapshot()`；`restore(state)`。

要修的行为：①长度小于 1e-6 的线段算退化，报 `FAN_DEGENERATE_SEGMENT`；同一 `seg_id` 重复注册报 `FAN_DUPLICATE_SEGMENT`；坐标非有限值报 `FAN_INVALID_SEGMENT`。②灯位必须有限、半径为正，`facing_deg` 与 `cone_deg` 必须成对且锥角在零到三百六十度之间，否则报 `FAN_INVALID_LIGHT`。③扇区起止角取端点相对灯位的方位角并归一到零到三百六十度，角差超过一百八十度时取补角方向，单段角宽不超过一百八十度。④两段扇区重叠或间隙不超过 `merge_epsilon_deg` 时合并，`seg_ids` 按起始角升序，合并次数进 `stats()["merged"]`。⑤锥形灯下两端都在照射锥外的线段不投影，但端点方位角仍按原值参与排序，不能整段跳过留下排序缺口。⑥合并后跨越零度的扇区要拆成零度两侧的两段，`sectors()` 里不得出现覆盖整圈的项。⑦被另一个扇区完全包含的线段阴影要剔除并计入 `culled`，避免同一处叠加两次颜色变深。⑧两端到灯的距离都超过半径的线段不投影，只记 `skipped_range`。⑨预算按每扇区两个端点顶点计，必须是不小于二的正偶数，否则报 `FAN_INVALID_BUDGET`；超限时按角宽从大到小保留，被裁的计入 `dropped`，保留项再按起始角升序输出，不能随机丢弃；裁剪结果只影响本帧输出，不得改动原始线段集合。⑩线段增删、预算变更、灯参数变更都要让已建扇区失效，此后 `fan_vertices`、`sectors`、`coverage` 报 `FAN_NOT_BUILT`，直到重新构建。⑪`fan_vertices` 每扇区返回灯位与起止端点三点；`remove_segment` 删不存在的线段报 `FAN_UNKNOWN_SEGMENT`。⑫快照含 `version`、`merge_epsilon_deg`、`vertex_budget`、`lights`、`segments`、`fans`、`stats` 七项且为深拷贝，结构不符报 `FAN_SNAPSHOT_INVALID` 且现有状态一字不动。

硬约束：多线程同时对同一盏灯调用 `build_fan` 时，同一输入只能真正构建一次，所有调用方拿到逐字段相同的扇区与顶点顺序；线段变更与构建并发时，结果只能反映变更前或变更后的完整状态，不能出现半个扇区。

`stats()` 至少含 `lights`、`segments`、`builds`、`merged`、`culled`、`dropped`、`skipped_range`、`invalidations`、`vertex_budget`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发构建与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: occluder_fan_builder
- typeName: OccluderFanBuilder
