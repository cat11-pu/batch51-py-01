# batch51-py-safety-c-04

## 题面

线上做实时音视频的那套服务这两周一直在抢 CPU：采集线程明明申请的是 fifo，跑着跑着被内核降回普通优先级，日志里只有一行看门狗超限；排查时又发现同一个租户下几个进程把组的额度吃满以后，后面的请求不是被干脆拒绝，而是卡在某个地方再也不动，运维只能挨个重启；更离谱的是有一次父组被人调小了额度，已经在跑的进程没人回收，新申请却全都撞在"额度不足"上，账面数字和实际占用差了将近一倍，监控面板上显示的额度和进程实际拿到的配额也对不上。

要做的是实时调度准入守卫，落在 gsb/batch51-py-safety-c-04，文件名 rt_sched_guard.py，主类 RtSchedGuard，构造参数 period_us 与 watchdog_cooldown_us。对外接口：create_group(name, *, parent=None, budget_us)、group_budget(name)、set_group_budget(name, budget_us)、admit(pid, *, group, policy, budget_us, now_us, allow_queue=False)、release(pid, *, now_us)、reservation_of(pid)、admissions()、queued()、pump(now_us)、watchdog(pid, *, now_us, reason="overrun")、cooldown_until(pid)、snapshot()、restore(state)、stats()。

要落实的边界：①组名重复抛 RT_GROUP_EXISTS，父组不存在抛 RT_GROUP_UNKNOWN，额度不是正整数抛 RT_INVALID_BUDGET，policy 只接受 fifo 与 rr，其余抛 RT_INVALID_POLICY；②组的已用额度是整棵子树里活跃预留之和，可用额度取自身剩余与父组可用额度的较小值，超额部分记在 over_us；③准入成功时按 sequence 递增记一条 admitted，额度按组累计且不得超过父组剩余额度，装不下时抛 RT_QUOTA_EXCEEDED，detail 给 group、requested、available；④同一进程重复申请同一策略只更新预算参数而不重复占用额度，释放时也只归还一次；⑤release 返回本次归还的额度，没有预留或重复释放返回 0；⑥看门狗触发后该进程降级为 other，归还额度并记下 cooldown_until，冷却期内它再次申请实时策略只能拿到普通优先级；⑦超出额度且 allow_queue 为真时请求进入等待队列，状态为 queued；pump 按到达顺序放行现在装得下的请求，装不下的留在原位且相对顺序不变；⑧父组额度被收缩到低于已分配总量时新申请一律拒绝，已运行进程不被强制回收，只标记超额；⑨允许上调组额度，上调后可用额度按新上限重算；⑩快照含 groups、reservations、queue、cooldown、sequence、stats 六项且与现场深拷贝隔离，restore 结构不合法抛 RT_SNAPSHOT_INVALID 且不改现场；⑪stats 暴露 groups、admitted、queued、rejected、released、demotions、restores 七项计数，admitted 含 pump 放行的条目；⑫reservation_of 没有预留返回 None，admissions 按 sequence 升序。

两条硬约束：并发准入同一组时只能按剩余额度依次成功，任意时刻已用额度不得超过上限，也不得把同一次请求重复计入；进程退出必须归还额度且不得重复归还，快照恢复后预留、队列、冷却与计数与快照一致。

验收：python3 -m pytest -q tests 的 15 条必须全过；不得修改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: rt_sched_guard
- typeName: RtSchedGuard
