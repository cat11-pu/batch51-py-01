# batch51-py-safety-c-18

## 题面

渲染机房的亲和配置这几天反复回滚：值班把一个租户的可用核从八核收窄到四核，已经绑在被摘掉核上的进程既不迁移也不报错，进程池一半卡死；另一台机器热插拔后，原先只绑两颗核的进程被写成全核可用，压测直接把整机打满；还有一次交集算成了空集，接口却返回成功，进程沿用旧亲和继续跑在越权的核上。范围是 gsb/batch51-py-safety-c-18 下的 sched_affinity_warden.py，类 SchedAffinityWarden，维护租户允许的处理器集合、在线处理器集合与各进程当前亲和。

公开接口：SchedAffinityWarden(*, cpus=(0, 1, 2, 3))；set_allowed(tenant, cpus)；allowed_for(tenant)；set_online(cpus)；register_process(pid, tenant, cpus)；unregister_process(pid)；apply(pid, cpus)；effective_set(pid)；reconcile()；history(pid)；snapshot()；restore(state)；stats()。拒绝时抛 SchedError(code, detail)。

要修的行为：① 构造参数 cpus 是机器可能的处理器集合，初始全部在线；set_allowed 对集合去重升序，不在可能集合里的处理器抛 SCHED_CPU_UNKNOWN，剔除离线后为空抛 SCHED_EMPTY_SET；② set_allowed 只保留在线处理器并返回实际生效的上限；allowed_for 对未登记租户抛 SCHED_UNKNOWN_TENANT；③ register_process 的生效集合必须同时落在租户上限与在线集合内，与请求集合取交集，交集为空抛 SCHED_EMPTY_SET 且不登记；进程号重复抛 SCHED_DUPLICATE_PID；④ apply 同样取交集，交集为空抛 SCHED_EMPTY_SET 并保留原亲和，请求里出现未知处理器抛 SCHED_CPU_UNKNOWN，未知进程号抛 SCHED_UNKNOWN_PID；⑤ 生效集合以冻结集合返回，effective_set 对未知进程抛 SCHED_UNKNOWN_PID；⑥ set_online 替换在线集合并返回新的在线元组，只接受可能集合内的处理器；⑦ reconcile 对全部登记进程重算并返回 checked、migrated、fallback、failed 四个计数，生效集合发生变化的计入 migrated；history 按发生顺序给出 epoch、desired、effective、reason 四字段；⑧ 重算得不到交集时回退到上一次成功生效的集合与在线集合的交集，仍为空则记为 failed，生效集合为空而不是全核可用；⑨ 允许集合收窄后，绑定到被移除处理器的进程要迁移到剩余核，迁移失败不得静默置为全核可用；⑩ 同一进程多次设置以最后一次为准，回退只回到本次设置前的集合，不得回到初始默认集合；⑪ unregister_process 成功返回 True、未登记返回 False；⑫ 快照为 {"tenants": {...}, "online": [...], "processes": {...}, "stats": {...}}，必须深拷贝，结构不符抛 SCHED_SNAPSHOT_INVALID 且原状态一字不动。

stats 返回 registered、applied、rejected、migrated、fallback、failed、hotplug 七个计数，reconcile 产生的迁移与回退都要累加进去。

硬约束：同一进程并发 apply 与 reconcile 时不能让生效集合停在半更新的中间态，最后一次成功的设置必须完整可见，计数不得丢；快照恢复后租户上限、在线集合、各进程亲和、历史与计数全部往返且不与入参共享内存。租户上限与在线集合是硬边界，任何路径都不得返回越界处理器。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与热插拔自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- name: batch51-py-safety-c-18
- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: sched_affinity_warden
- typeName: SchedAffinityWarden
