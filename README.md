# batch51-py-safety-b-20

## 题面

直播回传在弱网时段出现花屏和重复帧：抓包看到同一个序列号的包被上层消费了两次，重传包晚到又被当成新包投递；还有一路在重连之后仍然拿旧密钥发媒体包，接收端一直丢，值班只能整路重启。更麻烦的是重连后发送端继续用旧密钥，接收端整段丢弃，重传预算被迅速耗尽，画面卡住十几秒才恢复；事后核对发现序列号在回绕点附近还出现过一次误判，回放录像能看到明显的重复帧，值班复盘时才发现重传计数根本没有上限。范围是 gsb/batch51-py-safety-b-20 的 srt_arq_guard.py，类型 SrtArqGuard，负责发送端与接收端的序列空间、ARQ 窗口及加密握手。

公开接口：open_listener(stream_id, *, passphrase=None, latency_ms=120, window=16, initial_seq=0)；connect_caller(stream_id, *, passphrase=None, now=0)；submit_packet(stream_id, payload, *, now=0)；handle_ack(stream_id, ack_seq)；handle_nak(stream_id, seq, *, now=0)；receive_packet(stream_id, sequence, payload, *, now=0)；deliver(stream_id, *, now=0)；pending_packets(stream_id)；stream_state(stream_id)；retransmit_count(stream_id)；too_late_count(stream_id)；close_stream(stream_id)；key_material(stream_id)；snapshot()；restore(state)；stats()。拒绝时统一抛 SrtError(code, detail)。

要修的故障与边界：①流 ID 为空或超过 64 字符抛 SRT_INVALID_REQUEST，重复监听同一流抛 SRT_STREAM_EXISTS，流数超上限抛 SRT_CAPACITY_EXCEEDED；②监听端设置了口令时，呼叫方不带口令或口令不符一律抛 SRT_HANDSHAKE_FAILED，握手失败后监听端保持 listening，不得降级明文；③提交媒体包前必须处于 connected，否则抛 SRT_STREAM_STATE；④序列号是 32 位空间，按模差比较，初始序列由监听端配置，回绕后从 0 继续；⑤在途包数达到窗口上限后新包排队而不是丢弃，pending_packets 同时包含在途与排队，stats 的 queued 记累计排队包数；⑥handle_ack 推进窗口并回调排队包，重复 ack 返回 0 且不改状态，ack 超过已提交的最大序号抛 SRT_ACK_INVALID；⑦handle_nak 触发重传，同一包重传次数达到上限后按 too-late 丢弃、从待确认队列移除并计数，返回 None；⑧receive_packet 对重复序列号丢弃并返回 False，落后但仍在接收窗口内的乱序包要收下；⑨deliver 按序列号升序返回到期包，晚到包不阻塞后续；⑩重传包到达时若原包已被上层消费，必须按已交付丢弃而不是再次交付；⑪序列号回绕后旧包可能被误判为新包，必须按模差与到达时间双重判定；⑫同一 stream ID 重连后旧密钥不得复用，新握手完成前不得发送媒体包。

硬约束：并发 submit 按流串行，序列号不得重复发放；快照保存序列空间、在途窗口与接收缓冲，restore 后 next_seq、pending_packets、stream_state 都要在，发送窗口、接收缓冲与握手密钥必须一起进退，不能出现序列号重复发放或旧密钥继续加密媒体包的情况，非法快照抛 SRT_SNAPSHOT_INVALID 且不污染现有流。stats 至少返回 submitted、queued、acked、retransmitted、too_late 五个计数。

验收：python3 -m pytest -q tests 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发提交与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: srt_arq_guard
- typeName: SrtArqGuard
