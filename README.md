# batch51-py-safety-c-14

## 题面

采集侧多个租户共用一台宿主机，最近出现三类怪事：同租户两个进程先后打开同一个 pin，第一个进程退出后映射被判失效，另一个进程的操作全部失败，业务侧只能整体重启；pin 被改名后旧路径还能查到映射，运维按旧路径清理时误删了新映射，审计日志里句柄数与实际打开者数量也对不上；重启扫描时发现几个没有登记在册的 pin 路径，清理脚本一律按垃圾删掉，结果删掉了正在使用的映射。请修 gsb/batch51-py-safety-c-14 下的 bpf_map_pin_registry.py，类 BpfMapPinRegistry，维护 pin 路径到映射的归属、引用计数与孤儿登记。

对外接口：BpfMapPinRegistry(*, max_pins=32)；pin(path, *, tenant, map_id, owner_pid, owner_start)；lookup(path)；list_pins(tenant)；open_pinned(path, *, tenant, pid, start)；close_handle(handle_id)；refcount(path)；openers(path)；grant_cross_tenant(path, tenant)；unpin(path, *, tenant)；reclaim_orphans(alive)；scan(present_paths)；quarantined()；snapshot()；restore(state)；stats()。拒绝时抛 BpfError(code, detail)。pin 记录包含 path、tenant、map_id、owner_pid、owner_start、refcount、generation 七个字段；openers 按 pid、启动时间、租户升序返回三元组；stats 返回 pinned、opened、closed、unpinned、reclaimed、quarantined、refused 七个计数；snapshot 返回 version、pins、handles、grants、quarantine、next_handle、stats 七个键。scan 返回 stale 与 quarantined 两个升序路径元组，quarantined 返回全部隔离路径的升序元组，lookup 对未知路径返回 None。

要修的点：①pin 路径必须是绝对路径、不以斜杠结尾、不含空白，租户与映射名不能为空，进程号与启动时间必须为正，非法输入报 BPF_INVALID_REQUEST 且不留记录；②同一路径只能属于一个租户，重复 pin 报 BPF_PIN_EXISTS；③同一租户重复打开同一路径必须按打开次数累计引用，每次打开生成独立句柄，打开未登记路径报 BPF_PIN_NOT_FOUND；④关闭句柄逐个递减，只有计数归零才算无引用，重复关闭返回 False；⑤引用计数非零时 unpin 报 BPF_PIN_BUSY，计数归零后才允许摘除；⑥非属主租户打开需显式授权，未授权报 BPF_TENANT_DENIED，同一授权重复登记幂等；⑦非属主租户的 unpin 一律拒绝，属主在计数归零后重复 unpin 返回 False；⑧孤儿回收只处理创建者进程已退出的 pin，返回升序路径，创建者仍存活的不动，仍有活跃打开者的路径即使创建者退出也要保留；⑨pin 路径改名后旧路径登记必须失效，按旧路径查询与打开都不得命中新映射；⑩scan 对已登记但实际不存在的路径标记失效并移除，对实际存在但未登记的路径只登记为待审隔离，不能直接删除或当成可用映射；⑪pin 总数是硬顶，超限报 BPF_PIN_LIMIT；⑫快照深拷贝，restore 校验 pin 记录、句柄、授权、隔离集合与统计，非法报 BPF_SNAPSHOT_INVALID 且原状态不变。

硬约束：并发打开与关闭必须持锁，引用计数在任意并发下都要精确，句柄号不得重复，统计不得丢更新；快照恢复到新实例后句柄仍然可关闭、授权仍然有效、隔离集合与待审清单不丢，重启扫描以实际目录内容对账而不是信任登记表，对账结果要能重复执行且不改变已确认状态；pin 数量硬上限，孤儿回收与扫描都不得突破，任何清理动作都要先登记再执行。登记表是判定的唯一依据，任何未走登记的路径都不得进入可用集合。

验收：python3 -m pytest -q tests 15 条必须全过；不得改测试、跳过或用固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: bpf_map_pin_registry
- typeName: BpfMapPinRegistry
