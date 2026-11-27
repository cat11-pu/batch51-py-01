# batch51-py-safety-c-06

## 题面

图形登录机这周连续报障：客户端换个地址连上来，截屏工具仍能拿到别人的画面；会话结束、账号切换之后，旧凭据还能继续注入键盘事件。现场记录显示，一个会话连开两个客户端时两把令牌都能截屏，会话关闭后权限位没有一起回收，同一秒签发两张凭据还会拿到同一个令牌，拒绝日志里只剩总数，分不清是地址不符还是权限不足。范围是 gsb/batch51-py-safety-c-06 的 display_access_guard.py，类 DisplayAccessGuard，负责本地图形会话的凭据签发、授权裁决与权限分级。

公开接口：DisplayAccessGuard(*, max_sessions=64, credential_ttl=300)；open_session(session_id, *, uid, display, seat, now)；issue_credential(session_id, *, client_addr, file_mode=0o600, now)；active_credential(session_id)；credentials_for(session_id)；authorize(token, *, client_addr, session_id, action, now)；grant_capability(session_id, capability, *, now=None)；revoke_capability(session_id, capability)；capabilities(session_id)；revoke_credential(token, *, reason="manual", now=None)；close_session(session_id, *, now=None)；sessions()；snapshot()；restore(state)；stats()。时间一律由调用方传整数秒，不读系统时钟；拒绝抛 DisplayError(code, detail)。

要修的行为：①会话号重复登记报 DISPLAY_SESSION_EXISTS，活动会话数超出 max_sessions 报 DISPLAY_CAPACITY_EXCEEDED；②凭据绑定会话、客户端地址与签发时刻，有效期 credential_ttl，到期后授权一律拒绝并报 CREDENTIAL_EXPIRED；③同一会话只允许一份有效凭据，再次签发要顶掉旧的，旧令牌判 CREDENTIAL_REVOKED 并计一次轮换；④授权按凭据不存在、会话已关闭、凭据已撤销、凭据已过期、会话号不符、客户端地址不符、文件权限过宽、权限位缺失的顺序判定，依次报 CREDENTIAL_UNKNOWN、SESSION_CLOSED、CREDENTIAL_REVOKED、CREDENTIAL_EXPIRED、SESSION_MISMATCH、CLIENT_MISMATCH、CREDENTIAL_MODE_TOO_WIDE、CAPABILITY_MISSING；⑤action 只有 screenshot 与 input 两类权限位，两类独立授予，capabilities 按字典序返回元组，未知能力报 DISPLAY_CAPABILITY_UNKNOWN，未知会话报 DISPLAY_SESSION_UNKNOWN；⑥关闭会话级联撤销该会话全部有效凭据并清空权限，返回值是本次撤销的凭据数，之后再用旧凭据授权报 SESSION_CLOSED，capabilities 返回空元组、active_credential 返回 None；⑦凭据文件权限除属主读写外还带组或其他位时该凭据判无效并拒绝连接，不能只告警后放行；⑧同一用户的两个会话之间默认互不可见，显式授予截屏不自动带来输入注入权限；⑨会话切换用户后旧凭据立即失效，即使新会话复用同一显示编号也不得沿用；⑩stats 返回 sessions_opened、credentials_issued、credentials_rotated、denied、revoked、sessions_closed 六项，每次拒绝都计数；⑪快照为 dict 深拷贝，含 version、sessions、credentials、capabilities、counters，counters 为 dict，调用方就地清空或改写任一表都不得影响运行中的状态，缺字段或类型不对报 DISPLAY_SNAPSHOT_INVALID 且不动现存状态；⑫sessions 只返回未关闭的会话，每条会话记录带关闭标记；authorize 返回 Decision(status、code、session_id、action、uid)，放行时 code 为空串；sessions 与 credentials_for 按登记顺序稳定返回，先签的凭据排在前面，不因并发签发改变已有条目顺序。凭据令牌为至少 16 个字符的不可预测串，同一秒内多次签发不能重复。

硬性约束：并发签发同一会话只能留一份有效凭据，被顶替的令牌全部作废，不能出现两个令牌同时可用，被顶替的令牌留在历史里可查但不能再用于任何动作；快照与恢复要能在进程重启后还原会话、有效凭据、权限位与计数，恢复后仍可正常裁决，恢复失败不能破坏正在运行的会话；会话总数、单会话凭据条数都有硬上限，超限报错不静默丢弃；所有拒绝都要落在计数上，供值班按会话逐条复盘。

验收：python3 -m pytest -q tests 跑满 15 条用例全过；测试不许改、不许跳过、不许按固定输入写死；并发签发与重启恢复自行写程序验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 系统安全
- type: Bugfix
- module: display_access_guard
- typeName: DisplayAccessGuard
