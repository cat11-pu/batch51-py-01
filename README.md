# batch51-py-game-b-13

## 题面

接触阴影上线后，角色脚边和枪械握把处全是脏边：前景轮廓内侧出现一圈黑边，远处天空被当成遮挡体，快速转身时阴影还拖出一条长长的尾巴。抓帧记录显示，半球步进的预算被个别像素吃光，整帧时间被拖长；切换相机后上一段历史还在参与累积。请修 `gsb/batch51-py-game-b-13` 的 `contact_shadow_tracer.py`，类 `ContactShadowTracer`：按深度缓冲沿法线半球步进，检出近距离遮挡后按厚度与距离衰减生成接触阴影，再与上一帧结果做时域累积。步数、厚度与权重非法时抛 `ShadowTraceError(code, detail)`，它继承 `ValueError`。

公开接口：`ContactShadowTracer(*, width=64, height=64, camera_id="cam-0", max_steps=8, thickness=1.0, step_size=1.0, history_weight=0.5, far_plane=100.0)`；`configure(**kwargs)`；`load_scene(*, surface, occluders)`；`trace_tile(x0, y0, x1, y1)`；`sample_occlusion(x, y)`；`occlusion_map()`；`accumulate()`；`reset_history(reason="manual")`；`stats()`；`snapshot()`；`restore(state)`。

要修的行为：①`configure` 的 `max_steps` 须为正整数，`thickness`、`step_size`、`far_plane` 须为正数，`history_weight` 落在零到一之间，违规抛 `SHADOW_INVALID_CONFIG` 且原配置不变。②`load_scene` 的 `surface` 与 `occluders` 必须是 height 行 width 列的规整网格，行长度不一致或行列数不符抛 `SHADOW_INVALID_SCENE`，未载入场景就追踪抛 `SHADOW_NO_SCENE`。③`trace_tile` 的矩形为闭区间，起点不得大于终点、不得越出画面，否则抛 `SHADOW_TILE_INVALID`。④遮挡判定以像素表面深度减去 `step_size` 的整数倍作为探针深度，遮挡体深度与探针之差落在零到 `thickness` 之间才算命中，强度按一减去差值比厚度衰减，多条命中取最大值。⑤只读取当前像素所在列的遮挡体，探针深度降到零以下立即停止，单像素步数不得超过 `max_steps`。⑥`sample_occlusion` 在从未追踪过的像素上抛 `KeyError`，坐标越界抛 `SHADOW_OUT_OF_RANGE`；存在累积结果时返回累积值，否则返回当前帧值。⑦`occlusion_map` 返回 height 行 width 列的网格，未追踪的像素填 `None`。⑧`accumulate` 按 `history_weight` 加权当前帧与历史，首帧直接取当前值，返回参与混合的像素数，并把累积次数加一。⑨`reset_history` 清空全部历史并返回清除的条目数，之后的查询回落到当前帧。⑩相机标识变化必须清空已追踪瓦片与历史但保留场景；分辨率变化除了清空还要作废场景，重新追踪前必须重新载入。⑪射线起点落在深度不连续处时该像素按无遮挡跳过，不能把前景自身的深度当成遮挡体。⑫探针越过远平面时按无遮挡结束，不能把背景天空算成遮挡体；时域累积在物体或相机快速移动时要按重投影误差缩短历史权重，避免阴影拖尾。

硬约束：瓦片可由线程池并行处理，四路与单路追踪同一帧必须得到逐像素相同的结果；每帧步进预算按像素封顶，超预算的像素退化为无遮挡而不是拖长帧时间；快照要能把配置、场景、当前帧、历史与计数一起恢复到新实例，结构不符抛 `SHADOW_SNAPSHOT_INVALID` 且现有状态不变。`stats()` 返回 tiles、pixels、steps、accumulations、resets。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发瓦片与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: contact_shadow_tracer
- typeName: ContactShadowTracer
