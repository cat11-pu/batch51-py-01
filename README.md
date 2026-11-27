# batch51-py-game-b-14

## 题面

环境光探针换成立方体贴图之后，天空盒在六个面的交界处出现一条亮线，天顶与天底附近明显发暗，远处高光的 mip 级别越高接缝越粗。美术把同样的六张面重新导入一次，生成的 mip 竟然和第一次对不上；某次面尺寸不匹配时工具直接崩掉，连是哪张面出的问题都没留下。请修 `gsb/batch51-py-game-b-14` 的 `cubemap_seam_mip_builder.py`，类 `CubemapSeamMipBuilder`：按立方体邻接关系生成 mip 链，采样时跨面取邻居并按立体角加权，保证面边界与极点没有接缝。面尺寸不一致或非二的幂抛 `CubemapError(code, detail)`，它继承 `ValueError`。

公开接口：`CubemapSeamMipBuilder(*, max_size=1024)`；`load_faces(faces)`；`build_mips()`；`mip_count()`；`level_size(level)`；`texel(face, level, x, y)`；`face(face, level=0)`；`sample(face, level, u, v)`；`edge_texels(face, edge, level=0)`；`validate()`；`snapshot()`；`restore(state)`；`stats()`。

要修的行为：①`load_faces` 必须给齐 +x、-x、+y、-y、+z、-z 六张面，缺面抛 `CUBEMAP_FACE_MISSING`，多余键抛 `CUBEMAP_FACE_UNKNOWN`。②每张面必须是正方形、行长度一致、六张面边长相同，否则抛 `CUBEMAP_INVALID_SHAPE`；边长必须是二的幂，否则抛 `CUBEMAP_SIZE_NOT_POWER_OF_TWO`；超过 `max_size` 抛 `CUBEMAP_SIZE_TOO_LARGE`。③纹素必须是零到二百五十五的整数，越界、负数、浮点或字符串一律抛 `CUBEMAP_INVALID_TEXEL`。④`load_faces` 返回面边长，六张面按上传内容原样保存为第零级，同时把面数写进计数。⑤`build_mips` 要求先载入面，未载入抛 `CUBEMAP_NO_FACES`，成功时返回各级边长组成的元组。⑥每一级只由上一级的二乘二邻域取整数平均、除不尽向下取整得到；重复构建输出逐字节一致，与字典装载顺序和线程分工无关。⑦mip 级数等于以二为底边长的对数加一，`level_size` 越界抛 `CUBEMAP_NO_SUCH_LEVEL`，`texel` 坐标越界抛 `CUBEMAP_OUT_OF_RANGE`；`edge_texels` 按 top、bottom、left、right 返回该边纹素序列，未知方向抛 `CUBEMAP_INVALID_EDGE`。⑧`sample` 用归一化坐标做双线性采样，落在纹素中心时精确返回该纹素，落在四个纹素正中时按下标权重混合。⑨面边界采样必须把相邻面的对应边纳入滤波，面内角落像素要同时采到两个相邻面的纹素。⑩极点附近的立体角权重明显大于赤道，不能等权平均，否则上下两面会偏暗。⑪边长为一的最后一级不再降采样，直接复制上一级的结果而不是生成空级；快照含 version、size、faces、mips、stats 五项且为深拷贝，结构不符抛 `CUBEMAP_SNAPSHOT_INVALID` 且现有状态不变。

硬约束：同一 mip 级必须在六个面全部完成后才对外可见，构建可被多个线程分面并行但采样不得读到半成品；重复构建是幂等的，同一输入两次构建结果逐字节一致；快照要把面数据、全部级别与计数一起恢复到新实例。`stats()` 返回 faces、size、levels、builds、samples；`validate()` 返回 ready、size、levels、issues 四项，未装载或未构建时 ready 为假且 issues 非空。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发构建与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: cubemap_seam_mip_builder
- typeName: CubemapSeamMipBuilder
