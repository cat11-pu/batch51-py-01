# batch51-py-game-b-06

## 题面

地形组的静态场景换成分块距离场之后，美术只挪了一块岩石，整关加载并没有变快，接缝处反而多出一道硬台阶：贴花穿模、角色脚底悬空。排查发现编辑后只重建了编辑点所在的那一块，相邻砖块的窄带还是旧距离，采样跨块插值时两边对不上。更隐蔽的是体积还没建完就开始查询，表面像被吹起来一样整体外扩，美术只能把整关重新烘焙一遍，一次二十分钟。请修 `gsb/batch51-py-game-b-06` 的 `sdf_volume_builder.py`，类 `SdfVolumeBuilder` 负责把静态网格烘焙成分块距离场、缓存窄带距离并支持局部重建，拒绝时统一抛 `SdfVolumeError(code, detail)`。

公开接口：`SdfVolumeBuilder(*, brick_size=8, voxel_size=0.25, band_voxels=2.0, max_bricks=256)`；`register_mesh(mesh_id, *, bounds, sample_fn=None, content_hash=None, path=None)`；`build(mesh_id, *, now=None)`；`brick_of(x, y, z)`；`sample(x, y, z)`；`apply_edit(mesh_id, *, bounds, content_hash=None, now=None)`；`invalidate(brick)`；`rebuild_pending(*, now=None)`；`brick_state(brick)`；`version_of(mesh_id)`；`ready_bricks()`；`pending_bricks()`；`snapshot()`；`restore(state)`；`stats()`。

要修的行为：①单块边长取 `brick_size * voxel_size`，`brick_of` 对三个轴分别向下取整，负坐标同样向下取整，落在块面上的点归入坐标更大的那一块；坐标非有限值报 `SDF_INVALID_ARGUMENT`。②`register_mesh` 要求 bounds 的 min 各轴严格小于 max，首次注册版本为 1；内容哈希变化时版本加一并把该网格全部砖块转为待构建。③`build` 只烘焙该网格待构建的砖块，返回报告里的 `built_bricks` 是本次真正烘焙的块数，结束后 `ready_bricks` 与 `pending_bricks` 互补。④节点值取采样函数在该点的高度，截断到正负 `band_voxels * voxel_size`，砖块记录本块的最小与最大距离。⑤`sample` 按三线性插值跨砖块读取节点值，结果绝对值达到窄带宽度时 `truncated` 为真，`brick` 是查询点所在块。⑥查询点落在尚未构建的砖块时按向外截断返回正窄带宽度并置 `ready` 为假，不能返回零把表面撑出去。⑦`apply_edit` 把编辑包围盒每轴外扩一个窄带宽度，凡与之相交的砖块一律转待构建，编辑范围跨块时两侧都要失效，未相交的缓存原样保留。⑧`invalidate` 对已待构建的块返回假，未知砖块报 `SDF_UNKNOWN_BRICK`，计数只记真正发生的失效。⑨`rebuild_pending` 重算全部待构建砖块，刷新 `built_at` 与 `build_count`，未失效的块保持原构建时间。⑩同一网格版本重复构建直接复用缓存；内容哈希相同但导入路径不同也视为同一版本，不得重复烘焙。⑪砖块总数受 `max_bricks` 硬顶，超限报 `SDF_CAPACITY_EXCEEDED`，注册失败不得留下半个网格。⑫快照含 `version`、`meshes`、`bricks`、`counters` 四项且为深拷贝，`counters` 要带齐五项计数，结构不符报 `SDF_SNAPSHOT_INVALID` 且现有状态一字不动。

硬约束：同一网格版本的并发构建只允许每块被烘焙一次，多路同时进来时各报告里 `built_bricks` 之和必须等于砖块总数，不能出现重复烘焙或半就绪块；采样只读完整砖块，构建中的块不得被插值读到；快照要能把构建到一半的体积连同待构建集合恢复到新实例继续重建。

`stats()` 返回 `bricks`、`ready`、`pending`、`built`、`reused`、`invalidated`、`samples`、`rejected`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发构建与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: sdf_volume_builder
- typeName: SdfVolumeBuilder
