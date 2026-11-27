# batch51-py-game-b-03

## 题面

换季之后云层开始出岔子：同一片山谷在两帧之间浮出两层错开的云轮廓，像双重曝光；镜头传送到地图另一端，云还黏在上一处的位置上慢慢跟着挪；性能预算收紧后云的整体位置挪了几十米，覆盖率却一点没变；雷雨转晴的那段过渡里，云底拖着一条硬边。复现条件是晴天转雷雨、相机跟着载具高速移动，把体积云关掉之后问题立刻消失。渲染组把范围定在体积云层，代码在 gsb/batch51-py-game-b-03 的 volumetric_cloudscape.py，类 Cloudscape，负责把天气图映射成覆盖率与云底高度，按视线步进累积密度与光照，再和上一帧做时域混合。

公开接口：Cloudscape(*, max_steps=64, min_steps=8, terrain_height=0.0, history_decay=0.9, reprojection_threshold=0.35)；set_weather(weather, *, now_ms=0)；current_weather()；sample_density(x, y, z)；integrate(frame, *, ray_origin, ray_dir, step_budget=None)；resolve()；invalidate_history(reason="")；set_camera(*, reprojection_error)；frame_state(frame)；snapshot()；restore(state)；stats()。拒绝时抛 CloudError(code, detail)。WeatherMap 记录 version、coverage、base_height、top_height、transition_ms；CloudFrame 记录 frame、weather_version、density、transmittance、steps、history_weight、history_valid。

故障与边界：

一、set_weather 的 version 必须严格大于当前版本，否则抛 CLOUD_WEATHER_STALE；coverage 必须在 0 到 1 之间、base_height 小于 top_height，否则抛 CLOUD_WEATHER_INVALID；成功时返回新版本号，current_weather 返回当前生效的天气图。

二、天气图换代时历史整体失效，不能沿用旧覆盖率，被丢弃的帧记录计入 frames_dropped。

三、sample_density 在云底与云顶之间返回当前覆盖率，之外返回 0；两张天气图过渡时按时间插值覆盖率，过渡期的历史权重还要按插值进度衰减，否则出现双重轮廓。

四、云层底部低于地形高度时按地形裁剪，裁剪后仍要保留被遮挡方向的密度用于透光。

五、integrate 的步进次数取 step_budget 与 max_steps 的较小值，未给预算时用 max_steps；预算低于 min_steps 时抬到 min_steps；超预算只降低采样密度，不改变云层位置。

六、视线穿不过云层时 density 为 0、transmittance 为 1；穿过云层时 transmittance 小于 1。

七、resolve 在没有历史时原样返回当前帧，history_weight 为 0、history_valid 为 False；有历史时按 history_weight 混合，混合权 = history_decay × 相机权重。

八、set_camera 的相机权重为 1 - reprojection_error / reprojection_threshold 并夹到 0 到 1；相机传送到远处、重投影误差超阈值时历史整份丢弃，而不是按权重混合。

九、invalidate_history 清空已存的原始帧与历史，返回清除的帧记录数。

十、frame_state(frame) 返回该帧的 CloudFrame，未记录返回 None。

十一、快照带走天气图、帧记录、相机权重与全部计数；快照带 version 字段，版本不认识或结构损坏抛 CLOUD_SNAPSHOT_INVALID，原状态保持不变。

十二、stats 固定返回 weather_sets、integrates、resolves、invalidations、frames_dropped、camera_updates 六个键。

硬约束：步进次数有硬上限，性能预算只允许降低采样密度；天气换代与相机传送必须整份丢弃历史，不允许半份沿用；快照跨重启恢复后天气版本与历史标记一致。

验收：python3 -m pytest -q tests 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: volumetric_cloudscape
- typeName: Cloudscape
