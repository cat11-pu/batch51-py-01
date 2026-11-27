# batch51-py-game-b-02

## 题面

头显合成端这两天收到的是同一类投诉：转头时画面整体往反方向滑一下，右眼总比左眼慢半拍，偶尔两只眼错开一条缝；掉帧之后画面被往上抬一截，再慢慢弹回去；远景天空和远处楼顶的边缘会被整屏宽地拉扯一圈。接上帧率监测后，问题只在高负载合成时出现，单独跑渲染线程一切正常，排除了姿态采样本身的抖动。合成组把问题定在迟锁重投影，代码在 gsb/batch51-py-game-b-02 的 late_latch_reprojector.py，类 LateLatchReprojector，按最新姿态把已渲染帧重投影到合成时刻，并记录每帧每眼的渲染姿态、合成姿态与预测时刻。

公开接口：LateLatchReprojector(*, min_horizon_ms=0.0, max_horizon_ms=40.0, focal=900.0, depth_epsilon=1e-3)；submit_pose(frame, *, eye, position, orientation, timestamp_ms)；pose_for(frame, *, eye)；prediction_horizon(*, render_time_ms, compose_time_ms)；reproject(frame, *, eye, depths, rotation_only=False)；late_latch(frame, *, compose_time_ms, depths)；mark_low_confidence(frame, *, eye, count)；frame_state(frame, *, eye=None)；drop_frame(frame)；snapshot()；restore(state)；stats()。拒绝时抛 ReprojectError(code, detail)。Pose 记录 frame、eye、position、orientation、timestamp_ms；HorizonPlan 记录 requested_ms、used_ms、clipped；ReprojectionPlan 记录 frame、eye、predicted_at_ms、used_horizon_ms、total_samples、low_confidence、reprojected。

故障与边界：

一、submit_pose 首次接受返回 True，姿态按原样保存为浮点元组；eye 只能是 left 或 right，否则抛 REPROJECT_INVALID_EYE。

二、同一帧同一眼重复提交只认第一次，迟到姿态计入 late_poses 并返回 False，不得覆盖已存的渲染姿态，也不得改写已经合成出去的结果。

三、prediction_horizon 的 requested_ms = compose_time_ms - render_time_ms，按 [min_horizon_ms, max_horizon_ms] 裁剪；被裁剪时 clipped 为 True，used_ms 要报告实际使用的时长，合成端靠它决定是否降级。

四、reproject 需要该帧该眼已提交姿态，否则抛 REPROJECT_NO_POSE；total_samples 等于传入深度个数，reprojected 为 True。

五、深度为 None 或小于等于 0 的像素按纯旋转近似并计入 low_confidence；深度为无穷的像素按最大深度处理，不能因除零把整屏位移拉飞。

六、late_latch 要求双眼姿态齐全，缺一眼抛 REPROJECT_MISSING_EYE；两眼必须使用同一预测时刻，返回 eye 到 ReprojectionPlan 的映射。

七、late_latch 不额外累计 reprojects，reprojects 只统计显式 reproject 调用；latches 统计成功合成次数。

八、mark_low_confidence 累加该帧该眼的低置信像素并返回累计值，count 为负抛 REPROJECT_INVALID_COUNT；该帧该眼还没有重投影结果时抛 REPROJECT_NO_POSE。

九、frame_state(frame) 返回 eye 到 plan 的映射，没有数据时返回空字典；给定 eye 时返回单个 plan 或 None。

十、drop_frame(frame) 删除该帧两眼的姿态与结果，返回删除的逐眼条数；掉帧补偿只按已提交姿态的外推差计算，不得借用邻帧姿态。

十一、快照带走姿态、plan 与全部计数，恢复后可以继续重投影；快照带 version 字段，版本不认识或结构损坏抛 REPROJECT_SNAPSHOT_INVALID，原状态保持不变。

十二、stats 固定返回 poses、late_poses、reprojects、latches、dropped、low_confidence 六个键。

硬约束：同一（帧、眼）的写入只允许一个写入者，迟到姿态不能覆盖已合成结果；快照跨重启恢复后姿态与低置信计数一致；预测时长有硬上下限；左右眼姿态必须来自同一预测时刻。

验收：python3 -m pytest -q tests 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: late_latch_reprojector
- typeName: LateLatchReprojector
