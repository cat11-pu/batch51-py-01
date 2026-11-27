# batch51-py-safety-b-10

## 题面

城域互联的两台边界设备凌晨同时报链路中断：监控上看会话一直是 up，实际上对端早就换了标识符，本地还拿旧值续着；另一侧收到了鉴别序列号被回退的报文，计数里看不出是回退还是重复包，值班只能按总失败数猜；还有一次探测周期恰好耗尽又收到合法控制包，这次真实中断被当成正常收包吞掉，事后没人能从计数里还原，只能按采集周期一条条对照日志。范围是 gsb/batch51-py-safety-b-10 的 bfd_session_guard.py，类 BfdSessionGuard，负责收包、计时推进、鉴别校验、对端查询、状态查询与快照恢复，拒绝一律抛 BfdError(code, detail)。

公开接口：BfdSessionGuard(*, detection_multiplier=3, min_tx_interval=50, auth_enabled=True, max_sessions=64)；create_session(session_id, local_discriminator, remote_discriminator=0, now=None)、receive(session_id, packet, now=None)、advance(now)、authenticate(session_id, packet)、set_auth_keys(session_id, key_id, secret)、rebuild(session_id, remote_discriminator, now=None)，另有 session_view、session_state、peer、timers、stats、snapshot、restore。

故障与边界：①会话按 session_id 登记，本地标识全局唯一，重复报 BFD_DISCRIMINATOR_TAKEN，会话数超 max_sessions 报 BFD_SESSION_LIMIT，初始状态 down、检测时间等于倍数乘最小发送间隔、下一超时时刻为空；②收包按 packet 里的 local_discriminator 与本地标识比对，不一致即丢弃并记 rejected，原因为 local_discriminator_mismatch，状态与定时器都不动；③合法控制包让状态前进一步：down 进 init，init 进 up，up 保持 up，一步不得跨级，返回结果 accepted 为 True、reason 为 accepted；④每次合法收包把下一超时时刻重置为 now 加检测时间，未到期的 advance 返回空元组，到期把会话置回 down、清空超时时刻并记 timeouts；⑤advance 返回本次超时的 session_id 元组，按到期时刻升序，同时到期的按 session_id 升序；⑥对端标识在可用状态发生变化时必须先回失效再重建，不能原地改写远端标识继续维持可用；⑦鉴别序列号要单调递增，序列号回退但不是重复包按鉴别失败丢弃，重复包只丢弃不计数，两类不能合并成同一统计；⑧检测时间用尽但恰好收到合法控制包时，必须先按超时判决再处理该包，顺序颠倒会掩盖一次真实中断；⑨鉴别密钥按会话登记，未知 key 校验返回 False 并计 auth_failures，序列号只在通过后更新；⑩rebuild 把会话置回 down、远端标识改成新值、鉴别序列号清零并清空定时器，本地标识不变，rebuilds 加一；⑪session_state 返回 down、init、up，peer 返回远端标识，timers 返回 detection_time 与 next_timeout_at 两个键；⑫stats 返回 created、transitioned、timeouts、auth_failures、duplicates、rejected、rebuilds。

硬约束：并发收包与计时推进时状态只能前进一步，统计与定时器不得半写入；快照固定 version、sessions、stats 三键，深拷贝，restore 校验结构与版本，缺键或类型不符报 BFD_SNAPSHOT_INVALID 且原状态不动，恢复后剩余检测时间与鉴别序列号继续可用，重启重新计时而不是立刻判超时。

验收：python3 -m pytest -q tests 15 条全过；不改测试、不跳过、不按固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- module: bfd_session_guard
- typeName: BfdSessionGuard
- file: bfd_session_guard.py
