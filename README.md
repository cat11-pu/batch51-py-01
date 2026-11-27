# batch51-py-game-a-09

## 题面

内测服连着报了三起副本卡死：一队人走到第二道门前才发现钥匙刷在门后面，另一队开局就有一整片区域根本连不通，还有一批种子每次重启生成的走廊都不一样，策划拿同一个编号复现不出来。生成器只盯着房间数量，没人校验钥匙顺序，也没有重试上限，预算一超就悄悄多摆两只怪。请修 `gsb/batch51-py-game-a-09` 的 `dungeon_layout_solver.py`，类 `LayoutSolver` 负责按种子生成房间、走廊与门锁并完成校验，入参非法抛 `DungeonError(code, detail)`。

公开接口：`LayoutSolver(*, monster_budget=12, chest_budget=4, max_attempts=4)`；`generate(seed, *, monster_budget=None, chest_budget=None)`；`validate(layout)`；`regenerate(seed, *, max_attempts=None, monster_budget=None, chest_budget=None)`；`describe(layout)`；`path_to(layout, target)`；`current()`；`snapshot()`；`restore(state)`；`stats()`。布局用冻结数据类 `Layout` 承载 seed、attempt、rooms、entrance、boss、corridors、doors、keys、monsters、chests、monster_budget、chest_budget 等字段。

需要落地的行为：①种子必须是非布尔整数，预算必须是非负整数，max_attempts 必须为正整数，否则抛 DUNGEON_INVALID_REQUEST；②同一逻辑种子必须产出逐字段一致的布局，房间、走廊、门、钥匙、怪物、宝箱只由显式 seed 派生，不得使用进程级随机、时间或哈希顺序，rooms 按房间 ID 升序存放，corridors 两端写成升序对，其余元组字段同样按规范化顺序存放；③每次生成记录 seed 与 attempt，首次生成 attempt 为 1；④generate 必须产出能通过 validate 的布局，全部房间从入口可达、boss 可达，允许存在不在主线上的死路房间；⑤怪物与宝箱总量受 monster_budget 与 chest_budget 硬顶，超出预算的尝试按失败处理；⑥validate 的判定顺序固定为结构、钥匙序、可达性、预算，命中即返回对应 reason，结构问题包括重复房间、走廊或门指向不存在的房间、自环、钥匙没有对应门、入口或 boss 不在房间表里、房间表为空，一律返回 DUNGEON_LAYOUT_MALFORMED 且 reachable 与 unreachable 都是空元组；⑦可达性按走廊与已取得钥匙的门反复扩展至不动点，报告里的 reachable 与 unreachable 都按房间 ID 升序；⑧怪物或宝箱总量超预算返回 DUNGEON_BUDGET_EXCEEDED，report 的 monster_total 与 chest_total 是实际总量；⑨describe 返回 seed、attempt、entrance、boss、rooms、corridors、doors、keys、monsters、chests、monster_total、chest_total、monster_budget、chest_budget 与 32 位十六进制 fingerprint，走廊两端规范化为升序对、各项按字典序排序，构造时元组顺序不同而内容等价的布局必须给出完全相同的描述与指纹；⑩regenerate 的第 1 次尝试与 generate(seed) 逐字段一致，成功后 attempts 为实际尝试次数、reason 为 DUNGEON_OK；⑪current 返回最近一次成功生成的布局，快照含 version、config、current、counters 四项且为深拷贝，结构不符抛 DUNGEON_SNAPSHOT_INVALID 且原状态一字不动。

钥匙房本身位于它所开启的那扇门之后时判定为不可解，即使把门当作通行后全图几何连通，也必须返回 DUNGEON_KEY_ORDER_UNSOLVABLE 而不是放行；多把钥匙对应同一扇门时任意一把可达即可开门，不得要求全部钥匙都可达；重生成达到次数上限后返回最后一次的失败原因和 DUNGEON_REGENERATION_EXHAUSTED，layout 为 None，不得把半成品布局交出去。

硬约束：generate、regenerate、validate 会被多路预生成进程并发调用，同一实例上并发生成同一 seed 必须给出相同指纹且计数器不丢；快照恢复后当前布局、配置与三个计数器完全一致；预算与尝试次数都是硬顶，超限报错而不是放宽条件。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发生成与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: dungeon_layout_solver
- typeName: LayoutSolver
