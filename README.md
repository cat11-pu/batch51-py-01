# batch51-py-game-b-01

## 题面

入秋后雨夜街景的反射开始出问题：积水里同一片像素整块发亮，镜头快速转身时闪烁更明显；美术把墙面换成哑光材质之后，旧采样还在沿用，墙角拖着一条残影；回放模式把时间轴往回拖，画面又冒出大片静止的错误噪点。客户现场只在雨夜和霓虹招牌这条街上稳定复现，白天和室内关卡都正常，工程组已经把采样日志压到单像素级别，确认不是降噪器的问题。渲染组把范围收到像素蓄水池这一层，代码在 gsb/batch51-py-game-b-01 的 restir_reservoir_guard.py，类 ReservoirGuard，负责每像素的蓄水池采样、上一帧历史融合与邻域合并，最后由 resolve 交出该像素的最终样本与权重。

公开接口：ReservoirGuard(*, max_samples=32, depth_threshold=0.05, normal_threshold=0.9, seed=20261127)；update_sample(pixel, *, sample_id, target_weight, depth, normal, frame)；merge_history(pixel, history)；merge_neighbors(pixel, neighbors)；validate_history(pixel, *, depth, normal, frame)；advance_frame(frame)；resolve(pixel)；pixel_state(pixel)；reset(pixel=None)；snapshot()；restore(state)；stats()。拒绝时抛 ReservoirError(code, detail)。ReservoirState 记录 pixel、sample_id、weight_sum、sample_count、depth、normal、frame、history_frame、history_valid；ResolveResult 记录 pixel、sample_id、weight、sample_count、history_frame、history_valid。

故障与边界：

一、首个候选无条件接收：weight_sum 等于候选权重，sample_count 为 1，history_frame 为 -1，history_valid 为 False。

二、每接收一个候选 sample_count 加一、weight_sum 累加候选权重；样本数到 max_samples 后仍允许新样本按概率替换（替换概率 = 新权重 /（原权重和 + 新权重）），权重和要按替换概率修正，不能简单截断后续候选；updates 按调用次数累计，与样本是否被保留无关。

三、resolve 的 weight 为 weight_sum / sample_count，只读当前蓄水池、不得修改其状态；未初始化像素 resolve 抛 RESERVOIR_UNKNOWN_PIXEL，pixel_state 返回 None。

四、历史校验用深度差与法线点积：超 depth_threshold 或低于 normal_threshold 整份拒绝，回退当前帧，计入 rejected_history。

五、历史帧号早于当前帧（回放、时间重置）时整份历史失效，不能只靠深度与法线侥幸通过。

六、merge_history 通过校验后记录 history_frame、置 history_valid，样本数按上限截断。

七、merge_neighbors 合并邻域样本时，每个来源样本的权重需按源像素的 sample_count 缩放，直接相加会整片偏亮。

八、max_samples 不大于 0 抛 RESERVOIR_INVALID_CONFIG；sample_id 为空或全空白、target_weight 非正抛 RESERVOIR_INVALID_SAMPLE。

九、reset(pixel) 只清该像素，reset() 清全部，stats 的 pixels 归零；重置时该像素的历史帧号与有效标记一并清掉。

十、快照带走全部像素、帧号与随机种子，恢复后权重序列可继续；快照带 version 字段，版本不认识或结构损坏抛 RESERVOIR_SNAPSHOT_INVALID，原状态保持不变。

十一、同一像素并发 update_sample 只允许一个写入者，计数与权重和不得丢更新。

十二、stats 固定返回 pixels、updates、merged_history、rejected_history、merged_neighbors、resets 六个键。

硬约束：同像素写入必须串行且可重入；快照跨帧恢复后随机序列与像素状态一致；每像素样本数硬顶 max_samples；邻域合并的样本来源不得混淆像素坐标。

验收：python3 -m pytest -q tests 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: restir_reservoir_guard
- typeName: ReservoirGuard
