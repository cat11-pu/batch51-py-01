# batch51-py-safety-d-03

## 题面

周三凌晨的例行维护窗口，应用团队申请了关机抑制，结果机器还是在倒计时结束前被重启：值班查到持有者进程已经退出，抑制锁却一直挂着没人回收；另一个班次里，同一台机器上睡眠抑制和延迟抑制各有一把，释放其中一把时另一把也跟着失效，机器直接进了休眠；还有一次按键类抑制被当成关机否决，程序化的批量关机全被挡了下来。事后核对发现，倒计时的截止时间在新增延迟锁之后没有重算，重试关机又被报成另一种错误，维护窗口白白多耗了两小时；值班最后只能手工清空锁表再重启服务，清完又没人说得清哪些抑制其实还该保留。范围是 gsb/batch51-py-safety-d-03 的 inhibitor_lock_arbiter.py，类 InhibitorLockArbiter，负责 block 与 delay 两类抑制锁、持有者回收和关机倒计时。

公开接口：InhibitorLockArbiter(*, max_locks=256, max_locks_per_holder=8, delay_cap=300, holder_ttl=30)；acquire(holder, what, *, mode="block", delay=0, priority=0, reason="", now=0)；release(lock_id)；heartbeat(holder, *, now=0)；mark_holder_gone(holder)；expire(*, now=0)；query(what, *, now=0)；begin_shutdown(*, now=0, grace=60)；countdown()；lock_state(lock_id)；locks(*, holder=None)；snapshot、restore、stats。拒绝统一抛 InhibitorError(code, detail)。

要修的行为与边界：①acquire 校验 holder 非空、mode 只取 block 与 delay、what 只能由 sleep、shutdown、idle、handle-power-key、handle-lid-switch 组成且去重后按字典序返回、不得为空，block 不许带 delay、delay 必须大于零，违规抛 INHIBITOR_INVALID_REQUEST；②同一持有者、同一 mode、同一 what 集合重复申请合并回原锁并返回原记录，merged 加一，锁表不新增；③what 按集合求交，锁覆盖 shutdown 才否决关机，只覆盖 sleep 不影响关机查询；④block 直接否决，delay 只延长倒计时且合计延迟受 delay_cap 限制，结果状态为 blocked、delayed 或 allowed，blockers 与 delayers 都要返回；delayers 按 priority 降序、同优先级按申请先后排列，block 不受优先级影响；⑤持有者被标记消失后锁仍然生效，expire 之前不得放行，mark_holder_gone 返回该持有者当时的锁数，expire 回收已消失或租约到期的锁（now 减上次心跳大于或等于 holder_ttl）并返回数量，heartbeat 续租并返回锁数；⑥begin_shutdown 遇到 shutdown 的 block 锁抛 INHIBITOR_BLOCKED（detail 带 blockers），否则截止时间等于起算时刻加 grace 加 min（合计 delay，delay_cap），begin_shutdown 与 countdown 都返回 active、deadline、delay_total、blockers 四项，倒计时已存在时抛 INHIBITOR_ALREADY_SCHEDULED；⑦倒计时期间新增 shutdown 的 delay 锁要重算截止时间并计 deadline_updates，释放 delay 锁同样重算；⑧倒计时期间新增 shutdown 的 block 锁直接取消倒计时，deadline 置空并计 cancelled；⑨锁总数与单持有者锁数设上限，超限分别抛 INHIBITOR_CAPACITY（detail 带 limit）与 INHIBITOR_HOLDER_LIMIT（detail 带 holder 与 limit）；⑩同一持有者同时持 block 与 delay 时，释放其中一个不得让另一个失效；⑪delay 锁在倒计时未结束时遇到持有者崩溃，必须按剩余延迟立即重算截止时间，而不是等到原来那一份延迟走满；⑫handle-power-key 类抑制只影响按键处理，不得阻止程序化关机。

硬约束：并发 acquire 用 RLock 串行，合并结果与各项计数不得丢；快照含 version、locks、holders、countdown、stats 五项，与现场深拷贝隔离，非法结构抛 INHIBITOR_SNAPSHOT_INVALID 且不改现场；stats 返回 acquired、merged、released、expired、blocked_queries、cancelled、deadline_updates、restores 八项计数。

验收：python3 -m pytest -q tests 的 15 条全部通过，不得修改测试、跳过或按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: inhibitor_lock_arbiter
- typeName: InhibitorLockArbiter
