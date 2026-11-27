# batch51-py-game-b-17

## 题面

新版本地图的草丛在东侧区块密得连成一片，跨过区块边界就突然断掉，靠近水边的灌木还会长到崖壁正面；同一个种子在测试机重启后植被位置对不上，玩家看到的花丛凭空挪了几米；同一片区域在两台机器上生成的点数和朝向也不一致，回放录像里能直接看出差别。请修 `gsb/batch51-py-game-b-17` 的 `procedural_scatter_planner.py`，类 `ProceduralScatterPlanner` 按密度图与种子在区块内生成植被与道具的散布点，按坡度、高度、水域与排除区过滤，并按区块缓存供流式加载，拒绝统一抛 `ScatterError(code, detail)`。

公开接口：`ProceduralScatterPlanner(*, chunk_size=32, cache_limit=16, chunk_point_cap=512, max_layers=16, max_chunk_coord=1000000)`；`set_seed(seed)`；`add_layer(name, *, density, seed_offset=0, min_height=None, max_height=None, max_slope=None, water_level=None, exclusion=None)`；`remove_layer(name)`；`set_terrain(height, slope=None)`；`place_chunk(cx, cy)`；`points_in_chunk(cx, cy)`；`evict_chunk(cx, cy)`；`cached_chunks()`；`chunk_of(x, y)`；`set_cache_limit(limit)`；`stats()`；`snapshot()`；`restore(state)`。

要修的行为：①种子必须是非负整数，缺省为零，改种子要让已缓存区块全部作废，否则报 `SCATTER_INVALID_SEED`。②密度须在零到一之间且每轴候选数能整除区块边长，步长取 `round(1/sqrt(density))` 且至少为一；密度越界或步长不整除都报 `SCATTER_INVALID_DENSITY`。③层名不得为空、不得重复，排除区必须是 `(x0, y0, x1, y1)` 且两轴都递增，否则报 `SCATTER_INVALID_LAYER`；删除不存在的层报 `SCATTER_UNKNOWN_LAYER`。④`place_chunk` 前必须先注册高度函数，否则报 `SCATTER_NO_TERRAIN`；没有任何层报 `SCATTER_NO_LAYERS`；区块坐标必须为整数且绝对值不超上限，否则报 `SCATTER_INVALID_CHUNK`；高度函数必须可调用，否则报 `SCATTER_INVALID_TERRAIN`。⑤每个区块的候选点按全局格坐标派生随机数，抖动只在自身格内，同一区块在任意加载顺序下逐点坐标与朝向一致，随机序列只由种子、层序号与全局格坐标决定，与遍历顺序无关。⑥高度带按左闭右开过滤，水域按低于水位的点剔除，坡度超过上限的点剔除，排除区按左闭右开剔除，被剔除数计入 `filtered`。⑦坡度函数缺省时要用相邻三角面法线估算，不得用高度差近似，陡坡上的草丛不能贴在崖壁上。⑧跨区块边界的候选点按全局格坐标取整判定归属，只能落在一个区块里。⑨密度为零的层仍占住随机数序列的位置，把某层密度调零不能让后续层的点整体平移。⑩每区块点数受 `chunk_point_cap` 硬顶，超出按格序裁剪并计入 `clipped`。⑪缓存按最近使用淘汰，读不刷新次序，缩容立即裁到新上限，上限必须为正整数否则报 `SCATTER_INVALID_CACHE_LIMIT`；被淘汰的区块再查报 `SCATTER_NOT_CACHED`。⑫快照含 `version`、`seed`、`chunk_size`、`cache_limit`、`chunk_point_cap`、`layers`、`terrain`、`chunks`、`stats` 且为深拷贝，结构不符报 `SCATTER_SNAPSHOT_INVALID` 且现有状态不变。

硬约束：同一区块被多路加载并发调用时只能真正生成一次，`stats()["placed"]` 必须等于唯一区块数；不同区块并行生成的结果必须与串行逐块生成逐字段一致；缓存区块数与每区块点数都受硬顶。

`stats()` 返回 `seed`、`layers`、`cached`、`placed`、`points`、`filtered`、`clipped`、`evicted`、`rejected`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发加载与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: procedural_scatter_planner
- typeName: ProceduralScatterPlanner
