# batch51-py-game-a-13

## 题面

新资料片开服后任务线投诉集中在阶段错乱：玩家接了第二步任务，第一步的传送门还亮着，点进去又回到旧场景；交完任务下线重上，本该消失的怪物还在原地；组队时队长切了阶段，进度不一样的队友被一起拉进去，卡在墙里出不来。范围是 gsb/batch51-py-game-a-13 的 phase_visibility_guard.py，类 PhaseVisibilityGuard，维护玩家持有的任务阶段、世界对象归属阶段，并回答某玩家此刻能看见哪些对象。

公开接口：PhaseVisibilityGuard(*, max_phases=256, max_objects=4096, cache_size=256)；register_phase(phase_id, *, quest_id, group, priority=0) 返回 PhaseSpec；register_object(object_id, phase_id)（phase_id 为空表示全局对象）；set_map(player, map_id)；set_progress(player, quest_id, step)；enter_phase(player, phase_id)、leave_phase(player, phase_id)、switch_phase(player, phase_id) 均返回 Transition；visible_to(player, object_id)；sync_party_phase(leader, members) 返回 SyncResult；active_phases(player)；remove_object(object_id)；snapshot、restore、stats。拒绝抛 PhaseError(code, detail)。

要修的行为：①阶段号、任务号、互斥组都不能为空，重名报 PHASE_ALREADY_DEFINED，阶段与对象数量分别受 max_phases、max_objects 硬顶，超限报 PHASE_CAPACITY_EXCEEDED 与 PHASE_OBJECT_CAPACITY_EXCEEDED；②同一互斥组内只能存在一个阶段，进入同组更高优先级的阶段要原子替换，返回值里的 removed 是旧阶段、added 是新阶段，旧阶段的对象立刻不可见；③重复进入同一阶段按幂等处理，applied 为假、added 为空，reason 记 PHASE_ALREADY_ACTIVE；④同组新阶段优先级低于当前阶段时进入失败，玩家保持原阶段，不得出现两个阶段同时生效或两个都不生效；⑤switch_phase 只替换目标阶段所在的互斥组，其他组的阶段原样保留，返回的 active 按阶段号字典序排列；⑥leave_phase 只对已生效的阶段有效，否则 applied 为假并记 PHASE_NOT_ACTIVE；⑦全局对象对所有玩家可见，阶段对象只对持有该阶段的玩家可见，未知玩家的 active_phases 为空元组；⑧组队同步只把队长阶段推给同地图且进度相同的成员，进度不同的成员收到拒绝原因而不是被强制拉入，accepted 与 rejected 都按玩家号升序；⑨成员参数必须是玩家号列表，空队长号、字符串或含非字符串元素的列表报 PHASE_INVALID_REQUEST；⑩阶段对象被删除后可见性查询返回不可见并清理缓存，不能因残留条目把已隐藏对象继续画出；⑪快照包含玩家当前阶段、地图、任务进度与计数器，恢复后可见性答案与恢复前一致；⑫同一玩家同一时刻的阶段集合在并发切换下只能落在切换前或切换后的完整视图，不能读到一半旧一半新。

硬约束：进入、离开、切换与可见性查询并发时持同一把锁，可见性结果必须对应某一次完整切换；快照整体替换，结构必须包含 version、phases、objects、players、counters、stats 六个键，结构不符报 PHASE_SNAPSHOT_INVALID 且不影响正在跑的查询；可见性查询有缓存，缓存条目数受 cache_size 约束。stats 返回 phases、objects、players、entries、switches、lookups。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: phase_visibility_guard
- typeName: PhaseVisibilityGuard
