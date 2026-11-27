# batch51-py-game-a-01

## 题面

运营侧上线邀请返利后人手一张工单：有玩家拉了三个小号，返利却记到了大号头上；有人退款撤销后邀请人账上还留着钱，财务月底对不上；还有人换绑邀请码没收到任何提示，第二天上线发现两边都不认账。风控复核时又发现两个小号共用一台设备，返利按三个账号各发了一遍，退款时却不知道该扣谁；客服按设备号追查，发现同设备的小号彼此还互相邀请，归属看着像个环。范围是 gsb/batch51-py-game-a-01 的 referral_reward_tree.py，类 ReferralTree，维护账号绑定、三级返利发放与追回。

公开接口：ReferralTree(*, max_levels=3, max_children=16, shares_bps=(10000,5000,2500), milestones=None)；register_account(account, *, device=None, now=None)；bind_invite(account, inviter, *, now=None)；record_milestone(account, milestone, *, now=None) 返回本次入账总额；claim_rewards(account)；clawback(account, milestone)；tree_of(account)；balance_of / claimable_of / pending_debt / reward_state；ledger_of(account)；ban_account(account)；snapshot / restore / stats。拒绝统一抛 ReferralError(code, detail)。

要修的行为：①账号与里程碑名去空白后不得为空，否则报 REFERRAL_INVALID_REQUEST；②register_account 建根节点、level 0、bound_at 记注册时刻，重复注册报 REFERRAL_ALREADY_EXISTS；③bind_invite 可为尚未登记的账号建档并绑定，邀请人必须已存在，否则报 REFERRAL_NO_SUCH_ACCOUNT，失败不得留下半个节点；④自邀或把上游绑到下游构成环一律报 REFERRAL_CYCLE，原树不动；⑤被邀请人已绑定其他邀请人时必须在写入前拒绝，错误细节不得回显原邀请人标识；⑥level 取邀请人 level 加一，第四级及更深的节点照常入树，深度上限只截断发放不截断归属；⑦record_milestone 按 shares_bps 向距离 1、2、3 的祖先发放，同一账号同一里程碑只结算一次，重复调用返回 0；⑧每节点绑定子节点数受 max_children 硬顶，超限报 REFERRAL_NODE_LIMIT；⑨被 ban 的账号连同子树不能再结算、也不能再被绑定，报 REFERRAL_ACCOUNT_BANNED；⑩clawback 沿结算时记下的付款路径原路追回，返回各付款人实际扣减额；⑪追回额超过可扣余额时只扣到零，差额记挂起欠款，后续返利先抵欠款再入账；⑫tree_of 按节点在前、子节点按账号升序的先序遍历返回。

硬约束：同一账号的绑定、里程碑结算与追回必须串行，并发登记同一里程碑只入账一次，八路同时提交也只能有一笔入账；发放与追回共用一本账，余额不得为负，可领金额、已领余额与挂起欠款分开记账，对账时两头都能对上；返利只按账号结算，设备维度只作风控标记，不得因为同设备而重复发放；快照要还原整棵树、里程碑集合、账本与计数，结构必须含 version、nodes、milestones、ledger、counters、stats 六个键，结构不符报 REFERRAL_SNAPSHOT_INVALID 且不污染现有状态；待追回金额与节点数各自受配置上限约束，绑定失败时树上不得出现孤儿节点。stats 返回 accounts、bound、milestones、paid、claimable、reversed、debt。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发结算、并发追回与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 游戏开发
- type: Bugfix
- module: referral_reward_tree
- typeName: ReferralTree
