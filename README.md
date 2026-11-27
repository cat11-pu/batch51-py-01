# batch51-py-game-b-18

## 题面

雪山上线后地表颜色一直在跳：同一条山脊上午还是草地，下午变成裸岩，远处瓦片偶尔整片发白，美术调一层材质的顺序就得整关重烘；同一瓦片隔两帧再合成一次，输出权重会有细微差别，测光图上的亮度条一直在动。定位在多层材质权重合成这一环：每像素的层数没有上限、权重没有归一、远处瓦片降级后整体偏亮，纹理数组槽位在流式加载里还会让正在合成的瓦片读到半更新状态。请修 `gsb/batch51-py-game-b-18` 的 `terrain_splat_composer.py`，类 `TerrainSplatComposer` 把每像素的多层权重合成为可采样的层索引与权重，拒绝统一抛 `SplatError(code, detail)`。

公开接口：`TerrainSplatComposer(*, max_layers=8, max_layers_per_pixel=4, max_slots=8, max_stored_pixels=4096, grid_limit=1024, merge_distance=64.0)`；`set_layers(names)`；`write_weight(x, y, layer, weight)`；`clear_pixel(x, y)`；`compose_tile(x0, y0, x1, y1, *, distance=None)`；`sample_layers(x, y)`；`set_residency(names)`；`residency_map()`；`set_distance_merge(threshold)`；`stats()`；`snapshot()`；`restore(state)`。

要修的行为：①层名不得为空、不得重复，数量超 `max_layers` 报 `SPLAT_LAYER_LIMIT`，空表报 `SPLAT_INVALID_LAYERS`；重设层表要清空权重、已合成瓦片与驻留表，按新的声明顺序给每层分配槽位，驻留版本加一。②权重必须非负且有限，负数报 `SPLAT_NEGATIVE_WEIGHT`，非有限值报 `SPLAT_INVALID_WEIGHT`，未知层报 `SPLAT_UNKNOWN_LAYER`，写入零即清除该层。③坐标必须落在 `grid_limit` 内，越界报 `SPLAT_OUT_OF_RANGE`。④已存像素数受 `max_stored_pixels` 硬顶，新像素超限报 `SPLAT_CAPACITY_EXCEEDED`，覆写已有像素不算新增。⑤瓦片是闭区间，起止倒置或越界报 `SPLAT_TILE_INVALID`；未合成过的像素查询报 `SPLAT_NOT_COMPOSED`；写入或清除权重后已合成瓦片失效，再查同样报这个码，直到重新合成。⑥合成时每像素保留权重最大的前 `max_layers_per_pixel` 层，超出部分丢弃并计入 `clipped`，保留层按权重降序、同权按层索引升序输出。⑦保留层权重要重新归一到和为一，四舍五入到六位小数后把余量补在最大的那一层，不能让整体变亮或变暗；归一化只按保留层的权重和计算，不能把裁掉的权重算进分母。⑧所有层权重为零的像素落到基础层并给满权重，不能除零也不能输出全黑。⑨只调整层的声明顺序只改槽位映射，不改合成结果里的层与权重。⑩远处瓦片按 `distance` 与 `merge_distance` 合并相邻层，合并后的权重和仍要是一，不能因四舍五入整体变亮或变暗。⑪驻留槽位在流式加载中稳定复用，释放出的最小槽位优先给新层；变更驻留表不得让正在合成的瓦片读到半更新映射，`TileResult.slots` 必须是变更前或变更后的完整映射；驻留版本从零开始，`set_layers` 与每次 `set_residency` 都让它加一。⑫快照含 `version`、`layers`、`weights`、`tiles`、`composed`、`residency`、`residency_version`、`config`、`stats` 且为深拷贝，结构不符报 `SPLAT_SNAPSHOT_INVALID` 且现有状态不变。

硬约束：多线程同时合成不同瓦片与切换驻留表时，每个 `TileResult` 只能携带一份完整的槽位映射，`residency_version` 与 `slots` 必须自洽；同一瓦片重复合成结果逐字段一致。层数、每像素层数与已存像素数都受硬顶。

`stats()` 返回 `layers`、`pixels`、`tiles`、`composed_pixels`、`clipped_pixels`、`merged_pixels`、`rejections`、`residency_version`、`version`。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发合成与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: terrain_splat_composer
- typeName: TerrainSplatComposer
