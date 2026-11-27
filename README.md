# batch51-py-game-b-08

## 题面

雨天版本上线后美术和关卡各报了一堆问题：露天石板路积水已经能照出人影，屋檐下的台阶却一直是湿的，玩家踩上去还在打滑；同一块地面在雨里越下越亮，材质每隔几帧闪一次，远处看像有人拿手电在扫；雪天切到雨天之后，所有表面像刚擦过一样瞬间变干，再从头开始湿，落差特别假。负责材质的同学说现在的更新是每帧直接改状态，采样时偶尔读到只更新了一半的表面。请修 `gsb/batch51-py-game-b-08` 的 `wet_surface_accumulator.py`，类 `WetSurfaceAccumulator` 按表面记录雨雪累积的湿度、按蒸发速率衰减，并在超过阈值时生成积水遮罩驱动材质混合，拒绝时统一抛 `WetSurfaceError(code, detail)`。

公开接口：`WetSurfaceAccumulator(*, max_surfaces=4096, puddle_threshold=0.6, base_roughness=0.85, wet_roughness=0.25, min_albedo=0.72)`；`register_surface(surface_id, *, sheltered=False, exposure=1.0)`；`set_precipitation(kind, *, intensity=1.0)`；`accumulate(surface_id, seconds)`；`evaporate(surface_id, seconds)`；`publish(*, frame=None)`；`wetness_of(surface_id)`；`surface_of(surface_id)`；`material_of(surface_id)`；`puddle_mask(surface_id)`；`snapshot()`；`restore(state)`；`stats()`。

要修的行为：①`register_surface` 的表面标识须非空字符串，`exposure` 取 0 与 1 之间且不含 0，重复注册报 `WET_SURFACE_EXISTS`，非法参数报 `WET_INVALID_ARGUMENT`；表面数受 `max_surfaces` 硬顶，超限报 `WET_CAPACITY_EXCEEDED`。②`set_precipitation` 只接受 rain、snow、none，`intensity` 取 0 到 1 闭区间，返回规范化后的 kind 与 intensity 两个字段。③降雨每秒累积系数 0.50、蒸发系数 0.10，降雪每秒累积系数 0.20、蒸发系数 0.04，无降水只有 0.10 的蒸发；单次推进的湿度增量等于累积项乘以强度与暴露度再减去蒸发项，最后夹在 0 到 1 之间。④遮蔽表面不接收任何新的降水，但已经湿的表面仍按当前降水类型的蒸发系数继续变干，不能因为进了屋檐就瞬间归零。⑤`evaporate` 是按秒计的强制干燥，只做扣减、结果不低于零，与 `accumulate` 共用同一份工作状态。⑥湿度上限为 1，反复推进不得越界，也不得因为封顶而产生额外事件。⑦更新的结果先落在工作状态，`publish` 才整体切换到已发布状态并推进帧号，`wetness_of`、`surface_of`、`material_of`、`puddle_mask` 一律只读已发布状态。⑧材质参数随湿度同向变化：粗糙度从 `base_roughness` 线性降到 `wet_roughness`，反照率系数从 1 线性降到 `min_albedo`，两者都随湿度升高而降低。⑨湿度达到 `puddle_threshold` 标记为混合，积水深度按超出阈值的比例在 0 到 1 之间换算；未达阈值深度为零。⑩积水成型后继续降水只加深深度，不得反复触发材质切换或造成闪烁，切换事件只在跨越阈值的那一次计数。⑪雨雪切换时按新的系数继续演化当前湿度，不得重置。⑫快照含 `version`、`surfaces`、`published`、`frame`、`config`、`counters` 六项且为深拷贝，同时保留工作状态与已发布状态，结构不符报 `WET_SNAPSHOT_INVALID` 且现有状态不变。

硬约束：湿度推进与材质采样并发时，采样只能读到上一完整帧的已发布值，不得读到只更新了一半的表面；八路同时推进不同表面后一次发布，所有表面的新值必须同时可见，计数不得丢；快照要能把未发布的中间湿度和已发布状态一起恢复到新实例，恢复后继续推进的数值必须与原来一致。

`stats()` 返回 `surfaces`、`accumulates`、`evaporates`、`publishes`、`puddle_events`、`rejected`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发推进与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: wet_surface_accumulator
- typeName: WetSurfaceAccumulator
