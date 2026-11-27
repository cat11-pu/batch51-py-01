# batch51-py-game-a-23

## 题面

跨服国战上线第一周，行军时间对不上：同样的起点终点，两支队伍差了十几秒才到；同一格同时到达的部队，结算顺序和出发顺序完全相反，先到的反而排在后面；有玩家用加速道具把剩余二十秒的部队一点，直接变成瞬移到点；维护重启之后，在途部队从地图上凭空消失，召回指令也报找不到部队。范围是 `gsb/batch51-py-game-a-23` 的 `troop_march_scheduler.py`，类 `TroopMarchScheduler` 负责行军计划、到达队列与召回，参数非法或状态不符抛 `MarchError(code, detail)`。

公开接口：`TroopMarchScheduler(*, max_marches_per_player=5, tile_capacity=3)`；`dispatch(troop_id, player, *, origin, target, speed, troops, at)`；`eta(troop_id)`；`arrive_queue(tile, *, at)`；`speed_up(troop_id, seconds)`；`recall(troop_id, *, at)`；`resolve_arrival(troop_id, *, at)`；`march_of(troop_id)`；`active_marches(player)`；`snapshot()`；`restore(state)`；`stats()`。

需要落地的行为：①行军距离取切比雪夫距离 `max(|dx|, |dy|)`，耗时按 `ceil(距离 * 1000 / 速度)` 毫秒计算，`arrive_at` 等于出发时刻加耗时，速度只接受 1 到 10 的整数；②`dispatch` 校验坐标必须是非负整数、兵力为正整数、起点与终点不能相同、部队号与玩家名不能为空，分别报 `MARCH_INVALID_COORD`、`MARCH_INVALID_SPEED`、`MARCH_INVALID_TROOPS`、`MARCH_INVALID_TARGET`、`MARCH_INVALID_REQUEST`；③同一 `troop_id` 在途时重复出征报 `MARCH_ALREADY_MARCHING`，结算之后可以用同一个编号再次出征并拿到新的出发序号；④每名玩家的在途部队数受 `max_marches_per_player` 硬顶，超出报 `MARCH_LIMIT_EXCEEDED`，其他玩家不受影响；⑤`arrive_queue` 只返回目标格一致、`arrive_at` 不晚于参数 `at`、仍处于行军状态的部队，按到达时间升序排列；⑥同一格同时到达的多支部队按出发序号排队结算，先出发先得；⑦`resolve_arrival` 在到达前调用报 `MARCH_NOT_ARRIVED`，重复结算报 `MARCH_ALREADY_RESOLVED`，未知部队报 `MARCH_UNKNOWN_TROOP`，返回该部队在本格的结算序号与队列中的下一支部队；⑧`recall` 对未知部队报 `MARCH_UNKNOWN_TROOP`、对已到达部队报 `MARCH_ALREADY_ARRIVED`，召回按已行进比例返程并返还部分体力；⑨加速道具在剩余时间不足一分钟时按整分钟扣减，多余时长折算返还，不能直接把部队清零瞬移；⑩目标格在行军途中被敌方占领时，到达部队转为驻守失败并原路返程，不能静默消失；⑪`active_marches` 按出发序号升序，`march_of` 对未知编号返回 `None`；⑫快照含 `version`、`config`、`marches`、`seq`、`counters` 五项且为深拷贝，恢复后按原 `arrive_at` 续算剩余时间，结构不符的恢复报 `MARCH_SNAPSHOT_INVALID` 且原状态一字不动。

硬约束：同一格的到达结算与召回会被多路战斗协程并发调用，同一支部队只能有一个结果生效，队列序号不得重复发放；到达队列与行军状态按服务器时间推进，进程重启后凭快照续算，重启不得把在途部队变成已到达或丢失；每名玩家的在途部队数与单格结算队列长度都有上限，超出按规则拒绝而不是静默截断。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发结算与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: troop_march_scheduler
- typeName: TroopMarchScheduler
