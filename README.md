# batch51-py-game-a-14

## 题面

跨服组队开放后，两支队伍合并的功能几乎每周都要回滚：有的团队合并完人数超了上限，系统先把人拉进来再踢掉几个；有的合并确认到一半，队长把原队伍解散，结果两边成员都变成无队状态；还有玩家的入队邀请在合并完成后自动变成新团队的邀请，点进去提示队伍不存在。范围是 gsb/batch51-py-game-a-14 的 party_merge_guard.py，类 PartyMergeGuard，负责发起、双队长确认、容量与等级区间校验、成员迁移和邀请清理。

公开接口：PartyMergeGuard(*, team_capacity=16, request_ttl=300.0, clock=None)；create_party(leader, *, max_size=8, level_min=1, level_max=999) 返回 PartyInfo；add_member(party_id, player, *, level=1, in_instance=False)；party_of(player)；members_of(party_id)；invite(party_id, player) 与 pending_invites(player)；propose_merge(from_party, into_party, proposer, *, now=None) 返回 MergeRequest；confirm(request_id, leader, *, now=None)；reject(request_id, leader, *, reason="", now=None)；apply(request_id, *, now=None) 返回 MergeResult；status(request_id)；disband(party_id)；snapshot、restore、stats。拒绝抛 MergeError(code, detail)。

要修的行为：①建队要求队长非空且未在任何队伍中，重复归属报 PLAYER_IN_PARTY，人数上限、等级区间参数非法报 MERGE_INVALID_REQUEST；②入队依次校验队伍存在、队伍未被合并锁定、玩家未归属、成员等级落在队伍区间、队伍未满，分别报 PARTY_UNKNOWN、PARTY_LOCKED、PLAYER_IN_PARTY、PARTY_LEVEL_OUT_OF_RANGE、PARTY_FULL；③邀请按队伍与玩家去重，重复邀请返回原邀请号，pending_invites 按邀请号升序；④发起合并要求两队都存在且不同、发起人是来源队队长、两队等级区间有交集，否则报 MERGE_UNKNOWN_PARTY、MERGE_SAME_PARTY、MERGE_NOT_LEADER、MERGE_LEVEL_MISMATCH，请求记录双方队伍、发起人、当前阶段、确认人列表与过期时刻，过期后确认报 MERGE_EXPIRED；⑤两名队长都确认后状态才从 proposed 变为 confirmed，同一位队长重复确认按幂等处理，不算第二次确认，非队长确认或拒绝报 MERGE_NOT_LEADER；⑥apply 只接受 confirmed 状态，否则报 MERGE_NOT_CONFIRMED，成功时把来源队全部成员迁入目标队并删除来源队，moved 按玩家号升序；⑦重复 apply 按请求号幂等，返回 applied 为真、moved 为空，不得二次迁移，已关闭的请求再操作报 MERGE_REQUEST_CLOSED；⑧合并请求未关闭期间两支队伍都不能再接受新成员，拒绝或回滚后重新放开；⑨合并后总人数超过团队上限时在确认阶段就拒绝，不能先迁移再踢人；⑩任一方队伍中有成员正在副本中时整次合并拒绝，而不是把该成员留在原队伍；⑪确认后任一方解散则整次回滚，apply 返回 rolled_back 且成员留在原队伍；⑫待处理的入队邀请在合并完成后按原队伍失效，不得自动转为新团队邀请。

硬约束：并发 apply 同一请求时只能有一路真正迁移成员，其余返回已合并结果，成员列表不得出现重复或丢失；快照整体替换，结构必须包含 version、parties、players、invites、requests、counters、stats 七个键，结构不符报 MERGE_SNAPSHOT_INVALID 且不影响在线队伍；团队人数受 team_capacity 硬顶。stats 返回 parties、players、invites、requests、confirmed、applied、rejected、rolled_back。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发与恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: party_merge_guard
- typeName: PartyMergeGuard
