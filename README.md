# batch51-py-safety-c-17

## 题面

容器平台的缺页代理这一周连着出单子：一个租户把实例数顶满之后，别的租户也跟着报配额已满；同一个实例先后登记两段内存区间，后一段把前一段覆盖掉，缺页落在夹缝里既没处理也没告警；事件队列堆到几万条，收尾时直接强关代理，重启后一批实例既没释放区间又进不了新请求，只能人工挨个清理。范围是 gsb/batch51-py-safety-c-17 下的 userfaultfd_budget_guard.py，类 UserfaultfdBudgetGuard，按租户登记缺页代理实例、注册区间、处理线程和事件队列。

公开接口：UserfaultfdBudgetGuard(*, queue_capacity=8, idle_timeout=30)；set_tenant_quota(tenant, *, max_instances, max_threads, queue_capacity)；register(instance_id, tenant, *, threads=0, now=None)；attach_range(instance_id, start, length)；detach_range(instance_id, start, length)；spawn_handler(instance_id, thread_id)；retire_handler(instance_id, thread_id, *, crashed=False)；enqueue_event(instance_id, event, *, policy="drop")；drain(instance_id, max_events=None)；release(instance_id, *, force=False, now=None)；rebuild(instance_id, *, threads=0, now=None)；recover(now=None)；describe(instance_id)；snapshot()；restore(state)；stats()。拒绝时抛 UffdError(code, detail)。

要修的行为：① 租户必须先 set_tenant_quota 才允许 register，否则抛 UFFD_TENANT_UNKNOWN；实例号全局唯一，重复注册抛 UFFD_DUPLICATE_INSTANCE；② 单租户实例数不得超过 max_instances，超出抛 UFFD_QUOTA_EXCEEDED，其他租户照常；配额收缩到低于当前用量同样拒绝且旧配额保留；③ 区间按 4096 对齐，start 非负、length 为正且对齐，否则 UFFD_RANGE_INVALID；④ 同一实例区间不得重叠，重叠抛 UFFD_RANGE_OVERLAP 且原有区间一条不动，相邻可以；⑤ 区间用左闭右开表示，attach 返回该区间元组，describe 按 start 升序给出全部区间；⑥ detach 必须落在已登记区间内，整段解除后 describe 的区间为空，越界抛 UFFD_RANGE_INVALID；⑦ 线程号在同一实例内唯一，重复抛 UFFD_DUPLICATE_HANDLER，超出租户 max_threads 抛 UFFD_THREAD_QUOTA_EXCEEDED；⑧ 实例队列容量取构造参数与租户配额的较小者，满了以后 policy="drop" 丢新事件计 dropped、policy="block" 不入队计 blocked，两者都不得覆盖已有事件，其他策略值抛 UFFD_POLICY_INVALID；⑨ drain 先进先出，max_events 限制条数，空队列返回空列表；⑩ 队列有事件或还有处理线程时 release 抛 UFFD_RELEASE_BUSY，detail 为 queued 与 threads 两个计数，force=True 才清队列、下线线程、释放区间并计 forced_discards；已释放实例再操作抛 UFFD_STATE_INVALID；⑪ 同一区间先整体登记再部分解除时，剩余子区间要重新登记才能收事件，不得整段失效；⑫ 处理线程异常退出后实例进入故障态，新事件不得继续入队，只能显式 rebuild 重建处理线程后恢复入队。

重启后先 restore 再 recover：未正常关闭的实例标记为 stale，静置超过 idle_timeout 由 recover 释放并返回 marked 与 reaped 两个计数；原本已正常关闭的实例保持 released，不得被重新打开或改动区间。快照为 {"tenants": {...}, "instances": {...}}，必须深拷贝，实例条目含 tenant、state、ranges、threads、queued、events；结构不符抛 UFFD_SNAPSHOT_INVALID 且原状态不变。stats 返回 registered、attached、detached、queued、dropped、blocked、drained、released、forced_discards、recovered。

硬约束：同一实例并发 attach、enqueue、drain 时区间表与队列不得丢事件、不得重排，各项计数必须原子；快照恢复后配额、区间、线程、队列、计数全部往返且不与入参共享内存。每租户实例数、线程数、队列长度都是硬顶。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与重启恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch51-py-safety-c-17
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: userfaultfd_budget_guard
- typeName: UserfaultfdBudgetGuard
