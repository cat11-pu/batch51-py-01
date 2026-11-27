# batch51-py-safety-a-06

## 题面

权限治理平台的季度复核这周连出三起投诉：一批本该在复核里收回的仓库权限，活动关闭后仍然有效；两个并行的活动把同一条权益各回收一次，台账上出现两条回收记录；还有一位复核人离职后，名下四十条没裁完的条目一直挂着，没人接手。运维怀疑活动快照和回收台账各记了一套：开启时冻结的权益与关闭时的实际状态对不上，转交与并发裁决也没有统一的落账口径。范围是 gsb/batch51-py-safety-a-06 的 access_review_campaign.py，类 AccessReviewCampaign，负责权益台账、复核活动快照、裁决与回收。

公开接口：AccessReviewCampaign(*, default_due_ticks=100, max_items_per_campaign=5000)；add_entitlement(subject, resource, *, now)；revoke_entitlement(entitlement_id, *, now)；entitlements(subject=None)；open_campaign(campaign_id, *, subjects, reviewers, now)；assign(campaign_id, *, reviewer, entitlement_ids, now)；decide(campaign_id, *, reviewer, entitlement_id, decision, now)；close_campaign(campaign_id, *, now)；reclaim(campaign_id, *, now)；transfer_reviewer(campaign_id, *, from_reviewer, to_reviewer, now)；items(campaign_id, *, reviewer=None)；campaign(campaign_id)；snapshot()、restore(state)、stats()。拒绝一律抛 CampaignError(code, detail)。

故障与边界：

①权益 id 按 ent-0001 递增，同一主体同一资源重复登记报 CAMPAIGN_ENTITLEMENT_EXISTS，空主体或空资源报 CAMPAIGN_INVALID_REQUEST；

②活动开启时按 subjects 冻结当时有效的权益，开启后新增的权益不进入本轮；快照版本自 1 递增，活动 id 重复报 CAMPAIGN_EXISTS，查询未知活动报 CAMPAIGN_NOT_FOUND；

③条目数超过 max_items_per_campaign 报 CAMPAIGN_TOO_LARGE，并且不能留下半个活动；

④只能分派给活动开启时登记过的复核人，否则报 CAMPAIGN_UNKNOWN_REVIEWER；分派写入 due_at = now + default_due_ticks；

⑤裁决只认被分派的复核人，其他人报 CAMPAIGN_NOT_REVIEWER；decision 只接受 keep 与 revoke，其余报 CAMPAIGN_INVALID_DECISION；

⑥同一条目只认第一次有效裁决，之后重复提交原样返回首次结果并计入 duplicates_ignored；

⑦还有未决条目时关闭报 CAMPAIGN_PENDING_ITEMS，detail 带未决数量；

⑧未关闭的活动不能回收，报 CAMPAIGN_NOT_CLOSED；回收只处理裁决为 revoke 的条目，重复回收返回空清单并把 replayed 置真；

⑨活动关闭前被撤销的权益，回收时必须跳过并记为已失效，不能因为快照里还留着就报错；

⑩复核人离职转交时，其名下未决条目改挂备用复核人并重置该条目的到期时间，转交不得改动快照内容；

⑪同一权益被两个活动的快照同时覆盖时，先关闭的活动回收后，后关闭的活动不得对同一权益重复回收；

⑫快照必须是深拷贝，字段固定为 version、next_entitlement、next_snapshot、entitlements、campaigns、reclaimed、stats，结构不合法报 CAMPAIGN_SNAPSHOT_INVALID 且原状态不变。

所有计数只在操作真正落账时递增，重复提交与跳过失效权益要分开记，不能混进回收数量。统计口径要与每次调用的返回值保持一致。活动状态只有 open 与 closed，条目状态为 pending、kept、revoked、reclaimed、invalid；items 按权益 id 升序，可按复核人过滤。

统计口径：stats 固定返回 entitlements_added、campaigns_opened、decisions_recorded、duplicates_ignored、items_reclaimed、skipped_invalid、transferred。

硬约束：同一条目的并发裁决只能有一条落账，计数不得重复；关闭与回收要能从中断点续做，快照恢复后活动、条目、回收台账、计数器完整还原；单活动条目数按上限硬顶。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过或用固定输入写死；并发与重启自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: access_review_campaign
- typeName: AccessReviewCampaign
