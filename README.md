# batch51-py-game-r-01

## 题面

周年庆版本上线后，抽卡相关的客服工单堆了一整屏：有玩家单抽垫到第八十九抽，十连第一抽还是紫光，后台却显示保底已经触发过；有玩家从常驻池切到限定池，垫了七十多抽的水位直接归零，切回来又白送一次保底；还有玩家的十连里明明白光一闪出了一张金，战绩却记成两次保底，补偿邮件发重了。运营复核时发现审计流水顺序也对不上，复盘时看不出每一抽当时的水位。范围是 gsb/batch51-py-game-r-01 的 gacha_pity_guard.py，类 GachaPityGuard，负责卡池登记、水位推进、软硬保底裁决、池组继承与抽卡审计。

公开接口：GachaPityGuard(*, max_pools=16, max_audit=256)；register_pool(pool_id, *, group=None, base_rate_bps=60, hard_pity=90, soft_pity=75, step_bps=600)；pool_view(pool_id)；current_counter(pool_id)；rate_bps(pool_id)；pity_left(pool_id)；draw(pool_id, *, roll)；draw_ten(pool_id, *, rolls)；switch_pool(source_pool, target_pool)；audit(pool_id=None)；snapshot()；restore(state)；stats()。登记与视图返回 PoolView，单抽返回 DrawOutcome，十连返回 TenPullReport，审计返回 AuditEntry 列表；拒绝与非法输入抛 GachaError(code, detail)。

要修的行为：①卡池名与池组去空白后不得为空，group 缺省等于池名；base_rate_bps 取 0–10000，hard_pity 至少 1，soft_pity 大于等于 0 且小于 hard_pity，step_bps 不为负；不合法报 GACHA_POOL_INVALID，重复登记报 GACHA_POOL_EXISTS，超过 max_pools 报 GACHA_CAPACITY，失败不得留下半个池。②水位从 0 起，roll 取 0–9999，roll 小于当前有效概率即自然出金并清零水位；未出金水位加一。③垫抽达到 soft_pity 后，下一抽有效概率为 base_rate_bps + (水位 - soft_pity + 1) * step_bps，封顶 10000，rate_bps 返回下一抽的有效概率。④未自然出金且这一抽会让水位到达 hard_pity 时强制出金并记一次保底触发；同一抽既是自然出金又踩到硬保底时只按自然出金记一次，保底触发次数不加，水位只清一次；触发保底的那一抽不得再计入下一轮水位。⑤保底计数按池组继承：switch_pool 只在同组生效，源池水位搬到目标池并把源池清零，返回搬运值；跨组报 GACHA_GROUP_MISMATCH，两边都不动；同池切换报 GACHA_POOL_INVALID。⑥十连必须正好十个 roll，按顺序逐抽结算；数量不对报 GACHA_BATCH_SIZE，任一 roll 非法报 GACHA_INVALID_ROLL，整批拒绝且水位、统计、审计都不动。⑦十连报告给每抽序号（自 0 起）、本批出金数、保底触发数与结算后水位。⑧未登记卡池的任何操作报 GACHA_UNKNOWN_POOL。⑨每次抽卡与继承都进审计：抽卡记一条 kind 为 draw，继承记一条 kind 为 carry、pool_id 为目标池、roll 为空的条目；序号从 1 连续递增，audit(pool_id) 按序号升序只给该池条目，只保留最近 max_audit 条。⑩每池累计总抽数、出金数与保底触发数，stats 返回 pools、draws、golds、pity_triggers、switches、carried。

硬约束：同一池的抽卡与继承必须串行，十六路并发抽卡不得丢水位或丢计数；十连整批原子，失败不得扣任何状态；审计长度与卡池数量都有硬顶；快照必须深拷贝并含 version、pools、audit、counters、stats 五个键，counters 含 seq、switches、carried，结构不符报 GACHA_SNAPSHOT_INVALID 且不污染现有状态，恢复后水位、审计、统计与计数一致。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 游戏、图形与多媒体
- sub: 其他
- type: Bugfix
- module: gacha_pity_guard
- typeName: GachaPityGuard
