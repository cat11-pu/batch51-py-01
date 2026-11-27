# batch51-py-safety-a-10

## 题面

访客账号这季度出了两次越权：赞助人被降权后，他邀请的访客还保留着原来的数据导出权限，直到到期；一位访客在到期前提交续期，审批跨过了到期时刻，期间账号一直在线；访客转交给新赞助人后，旧赞助人的撤销又把他停用了。访客账号没有独立身份源，权限完全来自担保关系，所以任何一次降权、续期和转交都要在同一本台账里算清。担保人离岗、访客长期不登录、同一访客被两个团队共用，都会让到期时间和权限范围变得说不清，安全团队要求每次变化都能从台账里复算。范围是 gsb/batch51-py-safety-a-10 的 guest_access_sponsor_ledger.py，类 GuestAccessLedger，负责担保关系、访问窗口、到期与续期。

公开接口：GuestAccessLedger(*, default_window_ticks=1000, renewal_window_ticks=200, max_guests_per_sponsor=20)；register_sponsor(sponsor_id, grantable, *, now)；update_sponsor_scope(sponsor_id, grantable, *, now)；invite_guest(guest_id, *, now)；bind_sponsor(guest_id, sponsor_id, scope, *, now)；request_renewal(guest_id, *, now)；approve_renewal(guest_id, *, now)；settle_expiry(*, now)；revoke_guest(guest_id, sponsor, *, now)；transfer_guest(guest_id, new_sponsor, *, now)；reconcile(*, now)；effective_scope(guest_id)；guest(guest_id)；guests_for(sponsor_id)；snapshot()、restore(state)、stats()。拒绝一律抛 GuestError(code, detail)。

故障与边界：

①赞助人 grantable 与访客 scope 统一去空白转小写去重升序；重复登记赞助人报 GUEST_SPONSOR_EXISTS，重复邀请报 GUEST_ALREADY_EXISTS，空标识报 GUEST_INVALID_REQUEST；

②邀请只建 pending 访客，绑定后才 active 并写 granted_at 与 expires_at = now + default_window_ticks；

③绑定 scope 超出赞助人可授范围报 GUEST_SCOPE_EXCEEDED，访客保持 pending；

④同一赞助人名下 active 访客数达到上限报 GUEST_CAPACITY_EXCEEDED；

⑤续期只能在到期前 renewal_window_ticks 内提交，过早报 GUEST_RENEWAL_TOO_EARLY，已有在途续期报 GUEST_RENEWAL_PENDING，没有在途续期时审批报 GUEST_RENEWAL_MISSING；

⑥审批通过后 expires_at 以审批时刻重算，renewal_pending 清零，granted_at 不变；

⑦settle_expiry 只停用 expires_at 不晚于 now 的 active 访客，记 expired，重复执行返回 0；

⑧只有当前赞助人能撤销，其他人报 GUEST_NOT_SPONSOR 且访客状态不变；

⑨担保人权限收缩后，名下访客的既有权限在下次评估时同步收缩，不能拖到到期；

⑩到期前一刻提交的续期若审批跨过到期时刻，账号须先停用再按续期结果恢复，不能出现无窗口在线；

⑪访客转交后，旧赞助人的撤销不得再影响该访客；转交时按新担保人可授范围重算交集，到期时间保持不变；

⑫快照字段固定 version、sponsors、guests、stats，结构不合法报 GUEST_SNAPSHOT_INVALID 且原状态不变。

绑定与转交都要重新计算权限交集，交集为空时账号不得保持在线；续期审批只认当前在途的那一次，重复审批按无在途处理。台账对外只暴露不可变视图，调用方拿到的对象不能反向改状态。guest、guests_for、bind_sponsor 遇到未知对象分别报 GUEST_UNKNOWN、GUEST_SPONSOR_UNKNOWN，guests_for 按 guest_id 升序。

统计口径：stats 固定返回 sponsors、guests_invited、guests_bound、renewals_requested、renewals_approved、expired、revoked、transferred，计数只在状态真正改变时增加。

硬约束：并发续期与到期结算同时命中同一访客只产生一种终态；重启后赞助人范围、访客窗口、续期在途状态按快照还原；访客权限不得超过赞助人可授范围。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过或用固定输入写死；并发与重启自行验证；只做本地实现，运行时不发送真实邀请邮件，确认与审批都通过方法调用完成。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: guest_access_sponsor_ledger
- typeName: GuestAccessLedger
