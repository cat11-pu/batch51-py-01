# batch51-py-game-b-12

## 题面

异步计算通道上线后，编辑器里偶发画面条带和 GPU 挂起：日志显示计算队列已经改完纹理，图形队列还在读上一帧的内容；有一次同一个缓冲被两个队列先后写入，提交序号乱序；现场重启之后，之前已经提交过的屏障又被重放了一遍，画面直接闪黑。请修 `gsb/batch51-py-game-b-12` 的 `queue_family_handoff.py`，类 `QueueFamilyHandoff`：记录每个纹理与缓冲当前归属的队列族和最近一次提交序号，在图形、计算、传输三族之间生成 release 与 acquire 屏障并校验提交顺序。非法队列、跨资源族移交与序号问题统一抛 `HandoffError(code, detail)`，它继承 `ValueError`。

公开接口：`QueueFamilyHandoff(*, max_resources=256)`；`register_resource(handle, *, kind="buffer", size=4096, owner="graphics", sequence=0)`；`release_to(handle, family, *, sequence)`；`acquire_from(handle, family, *, sequence)`；`handoff_barriers()`；`submit(sequence)`；`pending_owner(handle)`；`write_begin(handle, family, *, sequence)`；`owner_of(handle)`；`version_of(handle)`；`record_copy(handle, *, sequence)`；`snapshot()`；`restore(state)`；`stats()`。

要修的行为：①队列族只认 graphics、compute、transfer；缓冲可用于三族，图像只能归图形与计算族，图像移交传输族或任意未知族抛 `HANDOFF_INVALID_FAMILY`。②注册要求名称非空、`kind` 为 buffer 或 image、`size` 为正整数，重复注册抛 `HANDOFF_DUPLICATE_RESOURCE`，资源数量受 `max_resources` 硬顶，超限抛 `HANDOFF_CAPACITY_EXCEEDED`，未知句柄的归属、版本与待办查询抛 `KeyError`。③`release_to` 先校验目标族与资源类型的兼容性和提交序号，序号小于资源最近序号抛 `HANDOFF_SEQUENCE_REGRESS`；同一资源已有待完成移交时再次释放抛 `HANDOFF_ALREADY_PENDING`。④`acquire_from` 必须与待完成移交的目标族一致，否则抛 `HANDOFF_FAMILY_MISMATCH`；没有待完成移交抛 `HANDOFF_NOT_PENDING`；序号必须严格大于释放序号。⑤释放只登记待完成移交，归属仍留在源族；只有 acquire 成功才切换归属、内容版本加一并刷新最近提交序号。⑥同一资源在 acquire 完成前不得被新族写入，`write_begin` 在存在待完成移交或归属不符时抛 `HANDOFF_NOT_ACQUIRED`。⑦每完成一次移交要配对产出 release 与 acquire 两条屏障，`handoff_barriers` 按提交序号、资源名、阶段升序返回尚未提交的屏障。⑧`submit` 只提交已完成移交的屏障且一批整体生效，未 acquire 的 release 屏障必须留在队列里；提交序号回退抛 `HANDOFF_SEQUENCE_REGRESS`，已提交的屏障不得再出现在 `handoff_barriers` 中，重新提交同一序号也算回退。⑨同一队列族内部移交不需要屏障，只更新归属，屏障计数不得变化。⑩默认路径下资源只有一个归属族，注册时不接受第二个族，任何绕开 acquire 直接让另一族写入的调用按 `HANDOFF_NOT_ACQUIRED` 拒绝。⑪传输队列上的仅拷贝操作通过 `record_copy` 记录，不改变内容版本；快照含 version、resources、pending、barriers、last_submit、stats 六项且为深拷贝，结构不符抛 `HANDOFF_SNAPSHOT_INVALID` 且现有状态不变。

硬约束：多线程提交要按提交序号串行化，八路并发对各自资源释放与获取后归属与屏障计数必须一条不差；屏障批次必须整体生效，不允许只提交 release 而丢下 acquire；进程重启后按快照恢复待完成移交，已提交的屏障不得重放。`stats()` 返回 resources、handoffs、barriers、submitted、rejected。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发提交与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 图形渲染
- type: Bugfix
- module: queue_family_handoff
- typeName: QueueFamilyHandoff
