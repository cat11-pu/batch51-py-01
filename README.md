# batch51-py-game-b-04

## 题面

烘焙组这周接到的是皮肤和蜡质道具的投诉：同一个角色在近景与远景下，脸侧那圈光晕亮度对不上；逆光时耳廓和鼻尖该透出的红边整片消失，正面打光反而把透光项算了出来；美术删掉一个旧剖面之后，引用它的材质直接把渲染线程拖崩。这三个问题在同一个版本里先后冒出来，美术和 TA 都以为是材质参数写错了，换过几轮贴图也压不下去；复核后确认近远景亮度差来自 LUT 构建方式，逆光缺失来自透射项符号，崩溃则是旧剖面被删除后引用关系没兜住。范围是 gsb/batch51-py-game-b-04 的 subsurface_profile_builder.py，类 SubsurfaceProfile，负责维护扩散剖面、可采样的剖面 LUT、厚度来源以及背光透射项。

公开接口：SubsurfaceProfile(*, default_profile="default", default_thickness=0.5, max_resolution=256)；define_profile(spec)；remove_profile(name)；build_lut(name)；sample_profile(name, distance)；thickness_from(name, *, thickness_map=None, uv=None)；transmission(name, *, light_dot_normal, thickness)；profile_versions()；snapshot()；restore(state)；stats()。拒绝时抛 SubsurfaceError(code, detail)。ProfileSpec 记录 name、radius、color、ior、resolution；LutHandle 记录 name、version、resolution、cached；ThicknessSample 记录 profile、value、degraded；TransmissionSample 记录 profile、transmittance、backlit、fallback。

故障与边界：

一、define_profile 首次返回版本 1，同名重定义版本加一；name 为空、radius 不为正、resolution 小于 1、color 不是三个 0 到 1 的数，抛 SUBSURFACE_INVALID_PROFILE。

二、build_lut 的分辨率取 spec.resolution 与 max_resolution 的较小值；同版本重复构建复用缓存，cached 为 True 并计入 lut_cache_hits，真正重建才计入 lut_builds。

三、同一剖面在不同分辨率下构建的 LUT 采样结果需一致，分辨率只影响精度、不影响能量守恒。

四、sample_profile 在距离 0 处归一为 1，按 exp(-距离 / 散射半径) 衰减；距离为负抛 SUBSURFACE_INVALID_DISTANCE。

五、厚度来源缺失时退化为常量 default_thickness 并标记 degraded；厚度图与剖面分开存储，降级只体现在采样结果上，不改动剖面本身；提供了厚度图却取不到对应 uv 时抛 SUBSURFACE_INVALID_THICKNESS。

六、transmission 在光源位于表面背面时按 exp(-厚度 / 散射半径) 计算；正面照射时透射项必须为零，不能取绝对值；厚度为负抛 SUBSURFACE_INVALID_THICKNESS。

七、剖面被删除后仍被材质引用时按默认剖面渲染并计入 fallbacks，不得中断渲染。

八、剖面切换原子替换，渲染线程不得读到半张 LUT；并发 build_lut 与 sample_profile 期间拿到的 handle 必须自洽，已经取到的旧版本 handle 仍可安全采样，不必加锁等待。

九、profile_versions 返回 name 到版本的映射，删除的剖面不再出现。

十、快照带走剖面、版本、LUT 缓存与全部计数；快照带 version 字段，版本不认识或结构损坏抛 SUBSURFACE_SNAPSHOT_INVALID，原状态保持不变。

十一、stats 固定返回 profiles、defined、removed、lut_builds、lut_cache_hits、samples、fallbacks 七个键。

硬约束：LUT 发布必须原子，渲染线程读到的 handle 与采样值来自同一版本；并发构建同一版本只做一次真正的构建；快照恢复后缓存热度与版本号一致。

验收：python3 -m pytest -q tests 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: subsurface_profile_builder
- typeName: SubsurfaceProfile
