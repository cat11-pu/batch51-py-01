# batch51-py-game-c-01

## 题面

上周版本上线后，主城大厅的卷积混响在切战斗音乐时会冒一声短促的咔哒，紧接着整条总线的尾音像被剪断一样消失，过一两秒再听又正常；画质拉高后的主播机上还有一类反馈：块大小调到 256 时，大厅那段教堂脉冲响应明显发干，像少了一截高频，块调小反而正常。运维在堆采样里也发现了问题，同一份两秒脉冲响应挂在八条总线上，常驻内存翻了好几倍。

范围收到音频引擎的卷积这一层，代码在 gsb/batch51-py-game-c-01 的 convolution_reverb_scheduler.py，类 ReverbScheduler，负责按音频总线维护卷积混响实例、切分脉冲响应、调度处理块并记录尾音与交叉淡化进度。

公开接口：ReverbScheduler(*, max_buses=8, max_partitions=32, head_samples=64, block_size=128, fade_blocks=4)；create_bus(name)；load_ir(bus, ir_id, *, taps)；swap_ir(bus, ir_id, *, taps)；set_mix(bus, *, wet)；process_block(bus, *, seq, samples)；tail_of(bus)；fade_progress(bus)；partition_count(bus)；release_bus(bus)；bus_state(bus)；snapshot()；restore(state)；stats()。拒绝时抛 ReverbError(code, detail)。IrBinding 记录 bus、ir_id、version、taps、head_samples、partitions；BlockResult 记录 bus、seq、samples、head_samples、partition_samples、tail_remaining、fade_remaining。

故障与边界：

一、总线名去掉首尾空白后才是身份，空串、纯空白、非字符串一律 REVERB_INVALID_NAME；重名报 REVERB_BUS_EXISTS；超过 max_buses 报 REVERB_CAPACITY。

二、第一条脉冲响应走 load_ir：版本从 1 起，分区数为 0（taps 不超过头段）或 ceil((taps - head_samples) / block_size)；分区数超过 max_partitions 报 REVERB_PARTITION_LIMIT，taps 非正或 ir_id 去空白后为空报 REVERB_IR_INVALID。

三、load_ir 只用于首次装载，已有脉冲响应再调报 REVERB_IR_PRESENT；换脉冲响应必须走 swap_ir，版本加一，ir_id 与当前相同直接报 REVERB_IR_UNCHANGED，还没有脉冲响应时报 REVERB_NO_IR。

四、set_mix 只接受 0 到 1 的实数（整数写法也收），越界报 REVERB_MIX_OUT_OF_RANGE，返回值是 float。

五、process_block 的 samples 必须是 1 到 block_size 的整数，0 或负数报 REVERB_BLOCK_INVALID，超过 block_size 报 REVERB_BLOCK_TOO_LARGE；没有脉冲响应报 REVERB_NO_IR。

六、每条总线的块序号从 1 起严格连续，跳号、重号、回退一律 REVERB_SEQ_MISMATCH；换脉冲响应不重置序号。

七、头段取 min(samples, head_samples)，剩下的样本走分区链，BlockResult 里两段相加必须等于本次 samples。

八、tail_of 与 BlockResult.tail_remaining 都按 taps 减已处理样本数计算，不足记 0；换脉冲响应后已处理样本数从零重新计。

九、swap_ir 把淡化窗口重置为 fade_blocks 乘 block_size；fade_progress 在窗口内是已消费样本除以总长度，窗口走完保持 1.0，没有进入淡化时是 0.0。

十、release_bus 返回该总线释放的脉冲响应引用数（没装载过记 0），总线随之消失，再访问报 REVERB_BUS_UNKNOWN。

十一、bus_state 返回 bus、ir_id、version、taps、partitions、wet、processed、last_seq、fade_remaining 与 retiring。

十二、stats 固定返回 buses、loads、swaps、blocks、samples、released 六个键；buses 是当前总线数，其余都是累计值。

硬约束：同一条总线的 process_block 会被多个渲染线程并发调用，序号必须原子推进，重复序号只能生效一次；切脉冲响应时旧链不得立刻静音，要按旧的 taps 把尾音输出完再释放，retiring 反映仍在输出的旧链条数；同一份脉冲响应被多条总线引用时只保留一份，最后一条总线释放后才真正卸载。快照要能带走总线表、脉冲响应版本、混合比例、已处理样本、最后序号与淡化进度，恢复后继续喂块的行为要和中断前一致；快照结构不认识或字段缺失时报 REVERB_SNAPSHOT_INVALID，原状态一字不动。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、跳过或按固定输入写死；并发与重启自行验证；只做本地实现，只用标准库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 音视频处理
- type: Bugfix
- module: convolution_reverb_scheduler
- typeName: ReverbScheduler
