# batch51-py-game-a-06

## 题面

赛季首周客服收到一批投诉：玩家在确认投降前的十几秒被网络踢出，排队入口被锁了半小时；另有两天机房抖动，整局被系统强制解散，第二天这些玩家仍带着惩罚点，排位入口直接灰掉。复盘发现离线掉线和主动退出被当成同一回事，重连没有撤销任何东西，服务器侧的故障也没有单独出口，客服只能手工给玩家补豁免，一天几十单，口径全凭个人经验。请修 `gsb/batch51-py-game-a-06` 的 `match_abandon_penalty_ledger.py`，类 `AbandonPenaltyLedger` 负责按对局与玩家记账，参数非法或状态不符抛 `PenaltyError(code, detail)`。

公开接口：`AbandonPenaltyLedger(*, grace_window=90, provisional_cooldown=300, max_points=12, daily_decay=1)`；`mark_leave(match_id, player_id, kind, *, at)`；`mark_reconnect(match_id, player_id, *, at)`；`settle_match(match_id, *, at)`；`waive_match(match_id, reason, *, at)`；`penalty_of(player_id, *, at=None)`；`tier_of(player_id, *, at=None)`；`queue_block_until(player_id, *, at=None)`；`standing_of(player_id, *, at=None)`；`records_for(match_id)`；`snapshot()`；`restore(state)`；`stats()`。

需要落地的行为：①kind 只接受 voluntary、disconnect、server_fault，结算点数依次为 3、1、0；②同一 (match_id, player_id) 重复上报只留一笔，后到的重复调用原样返回首笔记录且不增加任何计数；③mark_leave 时给退出方设置即时冷却 at + provisional_cooldown，server_fault 不设；④距离开时刻不超过 grace_window 的重连才算接受，返回的 accepted、within_grace、cooldown_cleared 均为真，grace_remaining 为剩余秒数，并清掉即时冷却；超出窗口一律拒绝，grace_remaining 为 0，冷却保持；宽限内重连只撤销即时冷却，结算时仍按退出计点；记录上的 reconnected_at 只在首次接受时写入，其后的重复重连不改写该时刻；⑤没有退出记录就重连抛 ABANDON_UNKNOWN_LEAVE；⑥结算按对局号幂等，重复结算原样返回首轮 awards 与 settled_at 并标记 duplicate，点数不得叠加，settlements 只加一、duplicate_settlements 单独累加；⑦结算按种别累加点数并封顶在 max_points，awards 报告封顶截断后实际记入的增量，按 player_id 升序，已豁免的记录跳过不计；⑧档位与冷却为 0–1 点 clean 不锁、2–3 点 watch 锁 300 秒、4–5 点 restricted 锁 900 秒、6 点及以上 suspended 锁 1800 秒，自结算时刻起算，queue_block_until 仅在结果大于传入 at 时返回该时刻，否则返回 None；⑨无记录的对局结算抛 ABANDON_UNKNOWN_MATCH；⑩快照含 version、config、records、points、cooldowns、settlements、stats 七项且为深拷贝，records 按 (match_id, player_id) 升序，结构不符的恢复抛 ABANDON_SNAPSHOT_INVALID 且原状态一字不动；⑪server_fault 种别不参与计点，记录在 records_for 里照常可见，豁免原因写成 server_fault。

这套台账还要向运营报表交付：按玩家能列出累计点数、当前档位和下次可排队时刻，同一对局的账只出现一次，重算历史对局不得二次扣点，报表读取期间不得看到只结算了一半的对局。

硬约束：同一对局的结算与重连会被多路网关并发调用，只能有一个结果生效，落败的一路返回 duplicate 为真；waive_match 用于服务器侧故障导致整局解散，全体记录豁免，已结算的点数回滚到该局结算前的值，重复豁免幂等；惩罚点衰减只在该玩家下一次结算时按整自然日结算一次，penalty_of、tier_of、queue_block_until、standing_of 都是纯查询，不推进衰减。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发结算与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: match_abandon_penalty_ledger
- typeName: AbandonPenaltyLedger
