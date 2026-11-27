# batch51-py-game-b-15

## 题面

光追场景改成实例化之后，每帧重建实例缓冲要几百毫秒：删除的实例 ID 从来没被回收，缓冲里空洞越来越多；同一个底层加速结构被十几个实例共用，删到最后一个时整块被提前释放，剩下的实例全变成黑块；还有些实例只是挪了位置，却把底层加速结构整块重建了一遍。更麻烦的是，掩码被清成零的实例会被当成已删除回收，同一帧里可见集合与实例缓冲对不上。请修 `gsb/batch51-py-game-b-15` 的 `ray_instance_ledger.py`，类 `RayInstanceLedger`：维护实例 ID 池、可见层掩码、变换脏标记与底层加速结构引用计数，供每帧稳定重建实例缓冲。重复 ID、越界掩码与负引用抛 `InstanceLedgerError(code, detail)`，它继承 `ValueError`；未知实例或未知底层结构抛 `KeyError`。

公开接口：`RayInstanceLedger(*, max_instances=1024)`；`add_instance(*, blas, transform=(0.0, 0.0, 0.0), mask=1, instance_id=None)`；`remove_instance(instance_id)`；`set_mask(instance_id, mask)`；`mark_transform(instance_id, transform)`；`ref_blas(blas)`；`release_blas(blas)`；`blas_refcount(blas)`；`instance_buffer()`；`visible_instances(layer_mask=0xFFFF)`；`rebuild_buffer()`；`allocated_ids()`；`free_ids()`；`snapshot()`；`restore(state)`；`stats()`。

要修的行为：①ID 池从一开始，删除后进入空闲池，新实例按最小可用 ID 复用；显式指定已占用 ID 抛 `LEDGER_DUPLICATE_ID`。②实例数量受 `max_instances` 硬顶，到顶后拒绝新增而不是覆盖已有实例，抛 `LEDGER_CAPACITY_EXCEEDED`。③新增实例必须引用已登记的底层加速结构，否则抛 `KeyError`；新增时该结构引用计数加一，实例默认标脏。④删除实例回收 ID 并把结构引用计数减一；未知 ID 的删除、改掩码、改变换一律抛 `KeyError`。⑤掩码必须是零到六五五三五之间的整数，越界抛 `LEDGER_INVALID_MASK`；`visible_instances` 按层掩码求交集并升序返回。⑥`mark_transform` 只更新变换并把实例标脏，不改变结构引用计数；`rebuild_buffer` 返回写入数、脏实例数与高水位三项，回写后清脏。⑦`instance_buffer` 按 ID 升序返回稠密快照，重复读取内容一致，之后新增实例不影响先前取到的缓冲。⑧同一底层加速结构被多个实例引用时，每次新增与删除都要准确增减，只有引用计数归零才从台账消失，计数不得落到负数。⑨掩码为零的实例仍占 ID 与缓冲位置，只是不参与求交，不能当成已删除回收。⑩仅变换改变时只更新实例数据，不触发底层加速结构重建或引用计数变化。⑪快照含 version、instances、free、blas、next_id、stats 六项且为深拷贝，结构不符抛 `LEDGER_SNAPSHOT_INVALID` 且现有状态不变。

硬约束：并发增删与缓冲读取必须串行化，八路并发各新增四个实例后 ID 不重不漏且缓冲保持稠密；容量是硬顶，到顶后既不分配也不给出半条记录；重启后按快照恢复 ID 池、空闲列表与引用计数，恢复后的下一次分配要和原实例一致。`stats()` 返回 instances、removed、rebuilds、dirty。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发增删与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: ray_instance_ledger
- typeName: RayInstanceLedger
