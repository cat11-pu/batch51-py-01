# batch51-py-game-b-20

## 题面

夜景切换成实时环境光后，画面里暗部出现整片噪点，亮部却均匀得像贴图；美术换了张环境贴图，采样表没有跟着更新，远处的灯箱和近处的烛光在采样里权重看着一样；同一帧里采样点数翻倍之后，直方图也和亮度对不上。定位在重要性采样表这一层：行边缘分布与条件分布分开算，别名表把余数概率取平均导致暗部过采样，局部更新只改条件分布让概率密度和采样对不上。请修 `gsb/batch51-py-game-b-20` 的 `importance_sample_table.py`，类 `ImportanceSampleTable` 从环境贴图亮度构建二维重要性采样表，拒绝统一抛 `TableError(code, detail)`。

公开接口：`ImportanceSampleTable(*, max_dimension=256, min_luminance=1e-12)`；`build(luminance)`；`sample(u, v)`；`pdf(x, y)`；`update_region(x0, y0, x1, y1, values)`；`rebuild()`；`row_distribution()`；`alias_table(row)`；`version()`；`stats()`；`snapshot()`；`restore(state)`。

要修的行为：①亮度表必须是非空矩形，行列数不超过 `max_dimension`，否则报 `TABLE_INVALID_SHAPE`。②亮度必须为非负有限数，负数或非有限值报 `TABLE_INVALID_LUMINANCE`；全表为零报 `TABLE_ZERO_LUMINANCE`。③`sample` 的 `u`、`v` 必须落在零到一之间，越界或非有限值报 `TABLE_INVALID_UV`，`u` 与 `v` 等于一时取最后一行最后一列。④采样先按行边缘分布定行，再按该行条件分布定列，`sample(0, 0)` 恒为左上角，结果与 `pdf` 一致；行与列的累积比较都用严格大于，落在分界上的取值归下一格。⑤`pdf` 返回该格亮度占总亮度的比例，未构建报 `TABLE_NOT_BUILT`，越界报 `TABLE_OUT_OF_RANGE`，分母是全表总亮度，局部更新后要跟着变。⑥`row_distribution` 按行号升序返回每行的边缘概率；`alias_table(row)` 每行条目数等于列数，概率在零到一之间且总和等于列数，别名下标合法。⑦别名表的余数概率要保留原始权重比，直接取平均会让暗部过采样。⑧亮度全零的区域仍要有非零概率兜底，否则采样会落到空区间产生除零。⑨`update_region` 是闭区间，值形状必须与区间一致，区间不得越界或倒置，否则报 `TABLE_INVALID_REGION`；负值报 `TABLE_INVALID_LUMINANCE` 且状态不变。⑩局部更新只重建受影响的行与边缘分布并让版本加一，更新后再查 `pdf` 与 `sample` 必须反映新值，旧的采样点不能落到新表之外的格子。⑪局部更新跨行时边缘分布与条件分布要一起更新，只改条件分布会让概率密度与采样不一致。⑫快照含 `version`、`luminance`、`row_sums`、`total`、`alias`、`stats` 且为深拷贝，结构不符报 `TABLE_SNAPSHOT_INVALID` 且现有状态不变。

硬约束：采样表可被多个采样线程并发读取，重建或局部更新期间读方只能看到完整的旧表或完整的新表，不能读到半更新的边缘分布；同一张表在任意线程上重复采样，`sample` 序列逐位一致；维度受 `max_dimension` 硬顶。

`stats()` 返回 `builds`、`rebuilds`、`updates`、`row_rebuilds`、`samples`、`rejections`、`version`、`rows`、`cols`，其中 `samples` 与 `rejections` 分别统计成功采样与被拒请求。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发采样与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: importance_sample_table
- typeName: ImportanceSampleTable
