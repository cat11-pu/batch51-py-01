# batch51-py-game-a-22

## 题面

阵营声望改版以后，公会战期间客服收到两类工单：连续刷同一副本的玩家第二天声望涨得比新玩家还慢，另一些玩家在敌对阵营地图做日常时声望被扣成负数，连原本已经解锁的军需官都点不开了；合服之后还有玩家发现自己在原服拿过的头衔奖励，在新服又领了一次。范围是 `gsb/batch51-py-game-a-22` 的 `faction_reputation_ledger.py`，类 `FactionReputationLedger` 按玩家与阵营记账，参数非法或状态不符抛 `ReputationError(code, detail)`。

公开接口：`FactionReputationLedger(*, daily_cap=1200, levels=(0, 500, 1500, 3000, 6000), decay=(1.0, 0.75, 0.5, 0.25), day=86400)`；`register_faction(faction, *, hostiles=())`；`award(player, faction, amount, *, source, at, event_id)`；`penalize(player, faction, amount, *, at)`；`points_of(player, faction)`；`level_of(player, faction)`；`daily_used(player, *, at)`；`unlock_check(player, faction)`；`transfer(player, source, target, amount, *, at)`；`snapshot()`；`restore(state)`；`stats()`。

需要落地的行为：①等级按阈值表取「已达成」的最大档位，0 点算 0 级，500 点升 1 级，1500 点升 2 级；②`award` 返回 `requested`、`granted`、`multiplier`、`points`、`level`、`duplicate`、`capped`，`granted` 是实际入账值；③同一声望来源在同一服务器日内按 1.0、0.75、0.5、0.25 逐次折算，每次向下取整，不同来源各自独立计数；④每日上限是硬顶，`granted` 被截断时 `capped` 为真，用满之后 `granted` 为 0、点数不再增长；⑤`event_id` 重复提交必须幂等，返回首笔结果并把 `duplicate` 置真，不得重复计入点数与每日用量；⑥金额非正报 `REP_INVALID_AMOUNT`，未知阵营报 `REP_UNKNOWN_FACTION`，空来源、空玩家、空 `event_id` 报 `REP_INVALID_REQUEST`；⑦敌对阵营的击杀惩罚不得把点数扣到当前等级下限以下，下限按已达成等级锁定；⑧`unlock_check` 返回自上次调用以来新跨过的等级并就地认领，重复调用返回空元组；⑨每日上限按服务器日切重置，跨日未领取的溢出声望直接作废、不结转；⑩`transfer` 从来源扣点并折算进目标阵营，转移上限取目标阵营当前等级的下一档阈值，超出部分按比例折算而不是全部丢失；⑪`daily_used` 是纯查询，只报告该服务器日已经入账的数量；⑫快照含 `version`、`config`、`factions`、`hostiles`、`points`、`daily`、`awards`、`unlocks`、`stats` 九项且为深拷贝，结构不符的恢复报 `REP_SNAPSHOT_INVALID` 且原状态一字不动。

硬约束：同一玩家的 `award` 与 `penalize` 会被战斗与任务两条链路并发调用，递减系数、每日上限与等级跨越必须在同一事务内判定，二十路并发也不得超发；`transfer` 与 `award` 同时对同一目标阵营生效时，目标点数不得越过下一档阈值；进程重启后从快照恢复点数、等级、每日用量、已认领等级与 `event_id` 幂等记录，重复提交仍按幂等返回首笔结果。

验收：`python3 -m pytest -q tests` 的 15 条用例必须全部通过；测试不得修改、不得跳过、不得按固定输入写死；并发调用与进程重启恢复请自行构造场景验证；接口签名、错误码与幂等语义以题面为准，不得自行增删；越界输入一律在写入前拒绝，不能落库后再回滚；只做本地实现，交付源码、测试记录与一份改动说明，改动不要提交到上游仓库。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: faction_reputation_ledger
- typeName: FactionReputationLedger
