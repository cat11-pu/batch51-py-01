# batch51-py-game-a-04

## 题面

赛季切换后客服收到两类工单：上赛季垫底的号新赛季第一把就排到了高分段，对手全是上赛季前一百；另一批人在定级赛里连输几把直接退出，分数照样掉，找客服要回滚。运营还发现同一赛季被人触发了两次重置，评分被压了两遍，榜首的分数比上赛季少了一大截；也有人反映重置当晚下线，第二天上线定级场次被清零，要从头再打，客服只能一个个手工改分。范围是 gsb/batch51-py-game-a-04 的 ladder_soft_reset_planner.py，类 SoftResetPlanner，做赛季软重置、评分压缩与定级赛进度。

公开接口：SoftResetPlanner(*, baseline=1500, keep_bps=5000, placement_matches=10, rating_floor=800, rating_ceiling=2000, placement_delta=25, uncertainty_start=100, uncertainty_step=100, uncertainty_cap=300, uncertainty_decay=40, uncertainty_floor=0)；register_player(player, rating, *, matches_last_season=0)；plan_batch(season, players=None) 返回批次标识；apply(batch_id, *, players=None) 返回 batch、applied、skipped；record_placement(player, *, won, completed=True, now=None)；rating_of / uncertainty_of / provisional_of / progress / state_of；snapshot / restore / stats。拒绝统一抛 LadderError(code, detail)。

要修的行为：①注册评分必须落在上下限内，越界报 LADDER_RATING_OUT_OF_RANGE，重复注册报 LADDER_PLAYER_EXISTS，空标识报 LADDER_INVALID_PLAYER，刚注册的玩家不是定级态；②批次标识由赛季与序号组成，形如 s2#1；③新赛季必须严格大于当前赛季，否则报 LADDER_SEASON_ORDER；④收件人列表为空或重复报 LADDER_INVALID_PLAYER，非法玩家整次拒绝、一个都不压；⑤压缩公式为 baseline 加上上季分与 baseline 之差乘 keep_bps 再整除 10000，结果按上下限截断；⑥压缩后不确定度取原值加 uncertainty_step 且不超过 uncertainty_cap，置为定级态并把场次清零；⑦上赛季没参赛的玩家只扩张不确定度、评分不动，同样进入定级态；⑧定级赛中途退出按弃权计入场次但不改评分，只有完成的定级赛参与定级计算；⑨完成一场定级赛按胜负加减 placement_delta，不确定度减 uncertainty_decay 且不低于下限；⑩定级场次达到 placement_matches 后转正式分，此后再报定级结果报 LADDER_NOT_PROVISIONAL；⑪progress 返回 played、needed、remaining 三个键；⑫同一赛季重复调用 plan_batch 返回同一批次标识，已应用的玩家续跑时被跳过而不是二次压缩。

硬约束：同一玩家的定级结果并发提交必须串行，二十路同时上报不能漏计也不能重复计，胜负加减与场次累加要一起生效；批量应用可中断续跑，重复应用同一批次不得把评分再压一次，续跑只压还没轮到的玩家、压过的保持原值，非法玩家整批拒绝时一个都不许先压，作废的旧批次不得再被应用；快照保存赛季、批次、玩家状态与计数，结构必须含 version、season、batches、players、counters、stats 六个键，结构不符报 LADDER_SNAPSHOT_INVALID 且不污染现有数据，恢复后定级场次能接着往下打。stats 返回 batches、players、applied、placements。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发上报与快照恢复自行验证，赛季数据要能导出复算；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: ladder_soft_reset_planner
- typeName: SoftResetPlanner
