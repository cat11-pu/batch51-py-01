# batch51-py-game-c-14

## 题面

客服中心这两个月收到大量通话断续的录音：网络抖一下之后，对方声音像卡带一样重复两个字，随后整段安静，直到下一句才恢复；有客户补发的语音包晚到，播放出来却被一串重复音盖住，时间轴还错位了半句；同一台服务器上跑着三路会议流，一路丢包之后另外两路也跟着出现杂音。范围是 gsb/batch51-py-game-c-14 的 audio_packet_concealer.py，类 AudioPacketConcealer，负责按序列号检测缺口、用历史波形补包、超限转静音。

公开接口：AudioPacketConcealer(*, frame_samples=160, history_frames=8, max_conceal=3, reorder_window=8)；push(stream, seq, samples)；gap_ranges(stream)；conceal(stream)；set_max_conceal(stream, frames)；set_sample_rate(stream, rate)；history(stream)；timeline(stream)；stats()；snapshot()；restore(state)；reset(stream=None)。拒绝一律抛 AudioConcealError(code, detail)。

要修的行为：

① 每个流独立维护起点、最高序列号、已收包、时间线与历史；stream 为空或不是字符串抛 AUDIO_INVALID_STREAM，seq 为负或不是整数抛 AUDIO_INVALID_SEQ。

② samples 必须是 frame_samples 个 -32768 到 32767 的整数，长度或类型不对抛 AUDIO_BAD_FRAME。

③ 序列号低于最高序列号减 reorder_window 视为回退，抛 AUDIO_SEQ_REGRESSION；窗口内的乱序包允许迟到。

④ 乱序到达但未超时的包不算丢失，不能提前生成伪造段；gap_ranges 只报告起点到最高序列号之间真正缺失的闭区间，升序合并。

⑤ conceal 把当前缺口补齐，每个缺口只补一次，第二次调用返回 0；返回值是本次补齐的包数，push 返回包在时间线里的下标。

⑥ 补齐用最近真实包的基音周期回绕复制：在 frame_samples//8 到 frame_samples//2 的滞后里取归一化相关度最高者，并列取最小滞后，伪造样本按该滞后循环取历史样本；历史为空时填零。

⑦ 连续丢失超过 max_conceal 后转为静音：前 max_conceal 个是伪造段，其余是零样本静音段；max_conceal 按流设置，负数或非整数抛 AUDIO_INVALID_LIMIT。

⑧ 迟到包到达后用真实数据替换伪造段，时间线长度与顺序不变，替换计数加一；重复到达的真实包直接忽略并计数，不得改变时间线。

⑨ 静音段之后的第一个丢失包不应复制静音，否则会把整段对话抹平；伪造只从真实历史取样。

⑩ 采样率切换要清空基音历史，沿用旧周期会产生明显音调跳变；rate 必须是正整数，流内历史与统计一并按新采样率重建。

⑪ 历史缓冲长度固定为 history_frames，只保留最近的包，内存不随通话时长增长。

⑫ stats 固定给出 streams、injected、concealed、silenced、replaced、duplicates 六项，injected 是接受的真实包总数（迟到替换也算一次）；snapshot 含 version、frame_samples、history_frames、max_conceal、reorder_window、streams，streams 下每流给出 base、highest、sample_rate、max_conceal、slots、history、counters，slots 按序列号升序，每项为（序列号，种类，样本）；snapshot 为深拷贝，restore 能恢复到新实例继续补齐，非法结构抛 AUDIO_SNAPSHOT_INVALID 且现有状态一字不动；reset 清空指定流或全部流。

硬约束：多路流会被不同解码线程同时 push 与 conceal，隐藏状态按流隔离，计数不得互相污染；同一流内一次补齐要么整段生效要么完全不生效；历史深度是硬上限。

验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: audio_packet_concealer
- typeName: AudioPacketConcealer
