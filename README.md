# batch51-py-game-b-10

## 题面

组队副本里名牌开始打架：二十多个单位站在一起时，血条叠成一坨，最上层的名字永远压着队长；被柱子挡住的目标整块消失，玩家以为人走了；镜头一转，名牌上下乱跳，鼠标点不到人。还有一次同一个 BOSS 在一帧里被两套逻辑各提交了一次位置，屏幕上出现两个一模一样的名牌，一个在旧位置，一个在新位置。请修 `gsb/batch51-py-game-b-10` 的 `nameplate_overlay_compositor.py`，类 `NameplateCompositor` 把角色头顶的名牌与血条投影到屏幕，按深度做遮挡淡出、按重要性分层，并在重叠时做稳定避让，拒绝时统一抛 `NameplateError(code, detail)`。

公开接口：`NameplateCompositor(*, width=1920, height=1080, max_plates=32, plate_width=120.0, plate_height=28.0, occlusion_alpha=0.25, occlusion_bias=0.05, offscreen_margin=64.0)`；`begin_frame(frame=None)`；`set_camera(*, eye=(0.0, 0.0, 0.0), fov_y_deg=90.0)`；`set_depth_probe(probe)`；`submit(entity, *, position, priority=0, text=None)`；`project(x, y, z)`；`resolve_overlap()`；`compose()`；`set_budget(max_plates)`；`destroy(entity)`；`plate_of(entity)`；`snapshot()`；`restore(state)`；`stats()`。

要修的行为：①实体标识须非空，位置必须是三个可转成浮点的有限值，优先级须为整数，否则报 `NAMEPLATE_INVALID_ARGUMENT`；同一实体在后续帧提交只更新位置与优先级，不新增第二个名牌。②同一实体在同一帧内被提交多次时只保留最后一次位置，不得生成两个名牌。③投影以相机 eye 为原点、朝负 Z 方向、上方向为正 Y：`dz = eye_z - z`，`dz` 不大于 0.1 时不可见，返回空；否则水平按 `(x - eye_x) / (dz * tan(fov/2) * width / height)`、垂直按 `(y - eye_y) / (dz * tan(fov/2))` 归一化后映射到像素坐标，返回 `(屏幕 x, 屏幕 y, 深度)`。④相机垂直视场角须在 0 与 180 之间且不含端点，eye 须为三个数值，非法报 `NAMEPLATE_INVALID_ARGUMENT`；深度探针必须是可调用对象。⑤名牌按固定板宽与板高居中占位，中心落在屏幕外扩 `offscreen_margin` 之外的一律剔除，剔除计数单独累计。⑥深度探针给出的场景深度小于名牌深度减 `occlusion_bias` 时判为被遮挡，透明度取 `occlusion_alpha`，保留轮廓淡出而不是整块去掉；未被遮挡的透明度为 1。⑦避让顺序按优先级降序、深度升序、实体标识升序，高优先级先落位；与已落位名牌相交时沿屏幕 y 轴向下平移最小整数倍板高，直到不再与任何已落位名牌相交。⑧两个同级名牌完全重合时按实体标识决胜，被挤开的一方只做最小位移，且该结果在下一帧继续沿用，镜头不动时不得左右横跳。⑨输出顺序固定为优先级降序再按实体标识升序，同一帧内重复调用 `compose` 与 `resolve_overlap` 结果逐项一致。⑩每帧名牌数受 `max_plates` 硬顶，超预算按优先级裁剪最低的那些，已保留名牌的坐标不得因为裁剪而改变；`set_budget` 只接受正整数。⑪实体被销毁后其名牌立即进入淡出队列，淡出期间不参与重叠避让，也不占每帧预算，不得继续影响其他名牌的位置。⑫快照含 `version`、`frame`、`plates`、`layout`、`counters` 五项且为深拷贝，结构不符报 `NAMEPLATE_SNAPSHOT_INVALID` 且现有状态不变。

硬约束：同一帧内多个系统线程并发提交不同实体时一条不能丢，提交与合成必须串行化，合成期间不得看到只写了一半的名牌表；裁剪与避让只改布局结果，不得改动提交时记录的世界坐标；快照要能把当前帧、全部名牌与上一帧布局一起恢复到新实例，恢复后同一相机与探针下合成结果逐项相同。

`stats()` 返回 `submits`、`frames`、`culled`、`dropped`、`pushed`、`rejected`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发提交与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: nameplate_overlay_compositor
- typeName: NameplateCompositor
