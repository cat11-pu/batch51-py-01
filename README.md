# batch51-py-safety-a-08

## 题面

客服中心这两周反复接到改绑工单：有人把登录邮箱改成另一个大小写写法，两步验证走完才发现和旧地址冲突；一个手机号被两个账号同时拿去改绑，两边都提示成功；还有账号被安全团队停用期间改绑照样生效，解除停用后又收到旧的确认链接。改绑是账号接管攻击最常见的入口，产品要求每次变更都能说清是谁在什么时刻确认了哪一侧，以及旧标识还要被占用多久。范围是 gsb/batch51-py-safety-a-08 的 account_identifier_change_guard.py，类 IdentifierChangeGuard，负责标识改绑的双方确认、占用与回滚。

公开接口：IdentifierChangeGuard(*, hold_ticks=500, request_ttl=300)；create_account(account_id, identifier, *, now)；initiate_change(account_id, new_identifier, *, now)；challenge_codes(request_id)；confirm_old(request_id, code, *, now)；confirm_new(request_id, code, *, now)；commit(request_id, *, now)；rollback(request_id, *, now)；release_hold(identifier, *, now)；resolve_login(identifier, *, now)；disable_account(account_id, *, now)；enable_account(account_id, *, now)；account(account_id)；change(request_id)；pending_change(account_id)；snapshot()、restore(state)、stats()。拒绝一律抛 IdentifierError(code, detail)。

故障与边界：

①标识统一去空白并转小写存储，重复注册报 IDENTIFIER_TAKEN，空账号或空标识报 IDENTIFIER_INVALID；

②每账号同时只允许一个在途申请，第二次发起报 CHANGE_IN_FLIGHT；申请号按 chg-0001 递增；

③challenge_codes 返回 old、new 两个六位数字串，同一申请重复读取结果不变；申请有效期 request_ttl，超时确认报 CHANGE_EXPIRED 并把申请置为 expired，账号标识保持不变，在途占位清空，可重新发起；

④旧标识确认码错误报 CHANGE_BAD_CODE，状态停在 awaiting_old；必须先完成旧标识确认，否则新标识确认报 CHANGE_STEP_OUT_OF_ORDER；

⑤两侧确认后状态为 awaiting_commit，未齐备时提交报 CHANGE_INCOMPLETE；

⑥提交成功把账号标识切到新值，旧标识进入 hold_ticks 的占用期，状态为 committed 并写入 committed_at，申请不再算在途；申请状态依次为 awaiting_old、awaiting_new、awaiting_commit、committed、rolled_back、expired；

⑦占用期内原账号用旧标识登录必须返回 redirect 并指向新标识；其他账号注册旧标识必须被拒；

⑧新旧标识相同或仅大小写不同，发起阶段就拒绝，不能走完两步确认再判冲突；

⑨在途期间账号被管理员停用，即使两侧都确认也不得提交；解除停用后申请作废，必须重新发起；

⑩rollback 只对已提交申请有效，回滚后账号恢复旧标识、新标识释放，状态为 rolled_back；对未提交申请调用报 CHANGE_NOT_COMMITTED；

⑪release_hold 只在占用到期时释放并返回 1，未到期返回 0，过期占用在重新注册时自动失效；

⑫快照字段固定 version、next_request、accounts、changes、holds、stats，结构不合法报 CHANGE_SNAPSHOT_INVALID 且原状态不变。

确认码只用于校验，不得落进任何日志；占用与释放的计数要能复算。申请一旦过期就不再接受任何一侧的确认。未知账号报 ACCOUNT_UNKNOWN，未知申请报 CHANGE_UNKNOWN。

统计口径：stats 固定返回 accounts、requests_initiated、changes_committed、changes_rolled_back、holds_released、confirmations。

硬约束：两个账号并发提交同一新标识只能一个成功，另一个报 IDENTIFIER_RESERVED；重启后占用期与在途申请按快照继续生效；每账号在途申请硬顶一个。

验收：python3 -m pytest -q tests 15 条全过；不得改测试、跳过或用固定输入写死；并发与重启自行验证；只做本地实现，运行时不依赖短信网关，确认码由进程内生成。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: account_identifier_change_guard
- typeName: IdentifierChangeGuard
