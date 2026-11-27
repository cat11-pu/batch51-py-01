# batch51-py-game-a-10

## 题面

任务链上线后玩家集体投诉保底不生效：连打四只怪都不掉任务物品，第五只才给，客服一查计数被别的任务蹭走了；组队刷本时队里一个人保底快满了，另一个离得半张图远也跟着拿保底；更离谱的是有人放弃任务再重新接，旧计数还在，一接就直接出货。掉落判定写成了全局一个计数器，队伍共享和任务隔离都没做。请修 `gsb/batch51-py-game-a-10` 的 `quest_drop_guarantee.py`，类 `QuestDropGuarantee` 按玩家与任务记录掉落尝试并在阈值处强制掉落，入参非法或状态不符抛 `QuestError(code, detail)`。

公开接口：`QuestDropGuarantee(*, threshold=3)`；`register_kill(player_id, quest_id, *, kill_id, monster_id, at)`；`roll_drop(player_id, quest_id, *, kill_id, base_drop)`；`credit_party(quest_id, *, kill_id, monster_id, participants, leader_id, at)`；`progress(player_id, quest_id)`；`configure_threshold(quest_id, threshold)`；`reset_quest(player_id, quest_id, *, reason)`；`kill_ids(player_id, quest_id)`；`snapshot()`；`restore(state)`；`stats()`。队伍成员用冻结数据类 `PartyMember(player_id, distance, level)` 传入。

需要落地的行为：①玩家、任务、击杀号必须是非空字符串，at 必须是非布尔整数，threshold 必须是正整数，base_drop 必须是布尔量，否则抛 DROP_INVALID_REQUEST；②register_kill 按玩家、任务、击杀号三者去重，重复上报返回 accepted 为假、duplicate 为真、kills 不变，duplicate_kills 加一；③同一玩家同一任务已登记的击杀号按升序保存在 kill_ids 里；④roll_drop 要求该击杀号已登记，否则抛 DROP_UNKNOWN_KILL 且不改任何计数；⑤未触发保底且 base_drop 为假时计数加一，返回的 dropped 与 forced 均为假；base_drop 为真时掉落、计数清零、item_count 加一、forced 为假；⑥计数加一后达到阈值时强制掉落，dropped 与 forced 均为真、计数清零、item_count 加一，这一笔不需要 base_drop 为真；⑦threshold 可按任务覆盖，configure_threshold 返回生效值并作用到该任务之后的全部判定，progress 的 threshold 与 remaining 按该任务生效值算，remaining 等于 threshold 减 counter；⑧不同任务的计数与物品数互不影响；⑨progress 对未登记的玩家与任务返回 registered 为假、计数与物品数为 0、threshold 取默认值；⑩快照含 version、config、quests、stats 四项且为深拷贝，quests 按玩家到任务两级嵌套，结构不符抛 DROP_SNAPSHOT_INVALID 且原状态一字不动；⑪stats 给出 kills、duplicate_kills、drops、forced_drops、resets 五项计数。

队伍成员距离超过 40 或与队长等级差超过 10 时不共享击杀计数，但仍各自记录自己的击杀；保底触发掉落的那一次击杀不再给其它任务计数，避免一次击杀同时推进多个保底；任务在保底临界点被放弃再重新接取时计数归零，不会带着旧计数直接触发保底。

硬约束：roll_drop 会被多路战斗服并发调用，同一玩家同一任务的计数推进必须串行，八笔并发未掉落恰好只应产出两次保底；保底计数有上限，永远不会越过阈值；快照恢复后计数、阈值、物品数与击杀号集合完全一致；击杀去重是幂等的，重复上报不能把计数推高。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发掉落与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: quest_drop_guarantee
- typeName: QuestDropGuarantee
