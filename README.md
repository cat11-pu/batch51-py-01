# batch51-py-game-b-05

## 题面

角色特写镜头换过之后，头发在远处开始出问题：同一束头发在近景和远景里的档位不一样，切过去时发根位置跳了一下，整体轮廓瘦了一圈；半透明发梢叠在一起时前后顺序每帧都在抖，逆光看过去像在闪；阴影贴图里发丝整片消失，只剩一张脸浮在空中；极端远处发丝干脆被裁成零段。这个问题在过场动画里最明显：镜头从主角推到肩膀，头发边缘会闪一帧黑边，远景剪影的轮廓也跟着抖。范围是 gsb/batch51-py-game-b-05 的 hair_strand_lod_builder.py，类 HairStrandLod，负责引导线聚类、LOD 选择、从属发丝插值、透明排序与阴影深度策略。

公开接口：HairStrandLod(*, lod_levels=3, segment_floor=1, merge_threshold=0.25, far_distance=40.0, coverage_thresholds=(0.5, 0.15))；build_strands(bundle, *, guides, children)；bundle_info(bundle)；select_lod(bundle, *, camera, coverage, distance)；interpolate(bundle, strand_id, *, lod)；sort_strands(bundle, *, camera, camera_position)；depth_policy(bundle, *, lod, shadow_pass=False)；strand(bundle, strand_id)；snapshot()；restore(state)；stats()。拒绝时抛 HairError(code, detail)。Strand 记录 strand_id、root、tip、segments、guide_id；BundleInfo 记录 bundle、guide_count、child_count、max_segments、bbox；LodSelection 记录 bundle、camera、lod、segments、child_ratio。

故障与边界：

一、build_strands 校验引导线非空、从属发丝的 guide_id 必须指向已存在的引导线、发丝 ID 不重复、segments 至少为 1，违反抛 HAIR_INVALID_BUNDLE；BundleInfo 的 bbox 覆盖所有发根与发梢，child_ratio 为从属发丝数除以发丝总数。

二、select_lod 按覆盖率选档：不低于 coverage_thresholds[0] 取 0，不低于 coverage_thresholds[1] 取 1，否则取最高档；distance 超过 far_distance 时档位再降一档，最高不超过 lod_levels-1。

三、同一束发丝在两个相机下 LOD 不同，排序键必须按各自相机计算，不能复用上一相机的顺序。

四、interpolate 每一档段数减半、向下取整，且不低于 segment_floor；发根与发梢端点不得移动，原发丝记录不被改写。

五、从属发丝在低档被合并到最近引导线时，若距离超过 merge_threshold 应保留为独立发丝，而不是强行吸附。

六、段数降到下限后仍要保留至少一段用于透光计算，不能退化为零段。

七、sort_strands 按相机到发根的深度升序，深度相同按发丝 ID 升序，按发丝 ID 列表返回便于上层逐条绘制；同一相机下重复调用结果稳定。

八、depth_policy 在阴影 pass 一律返回 shadow_write（低档也参与阴影深度写入），普通 pass 只有 lod 0 返回 write，其余返回 transparent_no_write。

九、bundle 不存在时抛 HAIR_UNKNOWN_BUNDLE，发丝不存在时抛 HAIR_UNKNOWN_STRAND。

十、LOD 切换必须保持发根位置与整体轮廓，插值权重按发根距离归一。

十一、快照带走发束、LOD 结果与全部计数；快照带 version 字段，版本不认识或结构损坏抛 HAIR_SNAPSHOT_INVALID，原状态保持不变。

十二、stats 固定返回 bundles、strands、builds、lod_selections、interpolations、sorts 六个键。

硬约束：LOD 切换与排序必须在单帧内原子完成，排序键不可跨相机复用；快照恢复后发束与 LOD 结果一致；段数有硬下限；同一相机下排序稳定。

验收：python3 -m pytest -q tests 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: hair_strand_lod_builder
- typeName: HairStrandLod
