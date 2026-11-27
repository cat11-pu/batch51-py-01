# batch51-py-game-a-08

## 题面

结算界面改版后，地图投票连着出岔子：上一局刚打过的沙漠图又进了候选，四张选票里两张指向正在维护的地图，截止前最后半秒有人改票，界面显示的地图和真正加载的对不上。运营要求投票按参与者名单发放，一人一票可以改，截止后给出唯一结果，并且同一场对局的重连玩家回来还能看到自己原来那一票。请修 `gsb/batch51-py-game-a-08` 的 `map_vote_ballot.py`，类 `MapVoteBallot` 负责一场对局的候选、选票与统计，入参非法或状态不符抛 `VoteError(code, detail)`。

公开接口：`MapVoteBallot(*, cooldown_matches=3)`；`open_ballot(match_id, *, participants, maps, recently_played=(), at)`；`ballot_state(match_id)`；`candidates(match_id)`；`cast_vote(match_id, player_id, map_id, *, at)`；`close_ballot(match_id, *, at)`；`result(match_id)`；`remove_candidate(match_id, map_id, *, reason, at)`；`mark_departed(match_id, player_id, *, at)`；`snapshot()`；`restore(state)`；`stats()`。

需要落地的行为：①participants 与 maps 必须是非空字符串元组且各自不重复，违反抛 VOTE_INVALID_REQUEST；校验入参在前，按 recently_played 裁剪在后；②recently_played 按最近在前排列，前 cooldown_matches 张进入 excluded，其余地图参与决胜：从未出现过的地图秩为 0，出现在 recently_played 第 i 位的地图秩为先后长度减 i，秩小者优先；③裁剪后候选为空抛 VOTE_NO_CANDIDATES 且不留下任何状态；④participants、candidates、excluded 一律升序返回，视图 votes 按 player_id 升序给出每位参与者的最终选择；⑤每个参与者一票可改票，改到不同地图时 revote_count 加一并返回新值，重复提交同一张地图返回 accepted 为假、reason 为 VOTE_UNCHANGED 且 revote_count 不变；⑥非参与者投票返回 accepted 为假、reason 为 VOTE_NOT_PARTICIPANT，投给不在候选里的地图返回 VOTE_UNKNOWN_MAP，两者都不改票也不计数；⑦map_id 传 None 表示弃权，返回 accepted 为真、reason 为 VOTE_ABSTAIN；⑧close_ballot 幂等，首次关闭记下 closed_at 并结算，再次关闭返回同一结果、closed_at 不变且 already_closed 为真；⑨tally 只按每位参与者最后一次选择统计，按地图 ID 升序完整列出全部候选含零票，abstained 为截止时没有有效票的人数，decided_by 在存在唯一最高票时为 votes、需要决胜时为 tiebreak、全程无人投票为 no_votes、有人投过但最终没有有效票为 all_abstained；⑩平票先比 LRU 秩，秩相同再比地图 ID 字典序，不得依赖字典遍历顺序；⑪查询未开启的投票抛 VOTE_UNKNOWN_BALLOT，result 对未关闭的投票返回 None，关闭后投递返回 accepted 为假、reason 为 VOTE_BALLOT_CLOSED 并计入 rejected 计数。

玩家在对局中途退出不影响投票资格：只要仍在参与者名单里，其选票在截止时照常计入。候选地图在投票期间因维护被移除时，投给它的票转为弃权，不得改投默认地图。关闭瞬间并发投递只能有一个结果生效，迟到票不改变已产出的结果但计入拒绝统计。

硬约束：关闭与投递会被多路网关并发调用，同一场对局只能产出一个结果，重复关闭不得改写 closed_at；快照含 version、config、ballots、stats 四项且为深拷贝，恢复后参与者、候选、选票、关票结果与计数完全一致，结构不符抛 VOTE_SNAPSHOT_INVALID 且原状态一字不动；选票与候选的排序只由显式字段决定，不得依赖字典遍历顺序或进程内随机。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过或按固定输入写死；并发关闭与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: map_vote_ballot
- typeName: MapVoteBallot
