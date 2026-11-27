# batch51-py-safety-r-07

## 题面

客服后台这周报上来一串怪事：用户点了登录之后，浏览器里的会话标识还是原来那个，测试同学拿着一份登录前抓到的 cookie 直接就能看到账户信息；另一台机器上，运营把一个带 Domain 属性的 cookie 存进来，浏览器把会话带到了别的子域，前端却显示一切正常；最糟的一次是同一账号在手机和电脑上反复登录，会话数没有上限，旧会话一直不失效，安全团队复盘时说不清哪些请求还算在登录态里。范围是 gsb/batch51-py-safety-r-07 的 session_fixation_guard.py，类 SessionFixationGuard，负责会话建立、登录与提权时的标识轮换、cookie 作用域校验，以及并发会话的裁决与审计。

公开接口：SessionFixationGuard(*, max_sessions_per_user=5, max_sessions_total=1000, idle_timeout=1800, cookie_name="__Host-SID")；create_session(*, user=None, fingerprint=None, now=None)；login(sid, *, user, fingerprint=None, now=None)；elevate(sid, *, level, fingerprint=None, now=None)；rotate(sid, *, fingerprint=None, now=None)；logout(sid, *, now=None)；revoke_user(user, *, now=None)；revoke_expired(now=None)；session_record(sid, *, fingerprint=None, now=None)；sessions_for(user)；sessions()；issue_cookie(sid, *, now=None)；validate_cookie(raw)；audit_log()；stats()；snapshot() 与 restore(state)。拒绝统一抛 SessionError(code, detail)。

要修的故障与边界：①会话标识是 32 位小写十六进制，重复创建必须拿到不同标识；新建会话代次为 0，匿名会话认证级别 0，带用户创建的直接是 1。②sessions_for 与 sessions 都按创建时间再按标识升序返回记录，未知用户返回空元组。③轮换后的新标识沿用原创建时间，rotated_at 刷新，代次加一，旧标识立刻按 SESSION_UNKNOWN 处理，不接受任何宽限。④提权只允许 1 到 3 级且必须严格高于当前级别，同级或降级报 SESSION_LEVEL_NOT_RAISED，越界报 SESSION_INVALID_LEVEL，失败不得改动代次。⑤logout 对已登出的标识返回 False 而不报错，撤销与过期清理都计入计数；revoke_user 只清目标用户的会话。⑥会话绑定了客户端指纹之后，指纹不符报 SESSION_FINGERPRINT_MISMATCH，且不得续期、不得轮换。⑦空闲超过 idle_timeout 的会话在取用时按 SESSION_EXPIRED 拒绝，但不就地删除，交给 revoke_expired 清理并计数。⑧未知标识在 rotate、login、elevate 上统一报 SESSION_UNKNOWN，并计入拒绝计数。⑨登录前就存在的匿名会话在登录成功后必须换发新标识，不能把原标识直接升级成已认证会话。⑩__Host- 前缀同时出现 Domain 属性时整条 cookie 拒绝，而不是忽略 Domain 继续放行；__Host- 还要求 Secure 与 Path=/。⑪单用户并发会话达到上限时踢最旧的一条，被踢会话的在途请求要按已登出处理。⑫全局会话总数有硬顶，超限报 SESSION_LIMIT_EXCEEDED；cookie 解析拒绝重复属性、未知属性、非法值以及 SameSite=None 未配 Secure。

硬约束：同一实例上的创建、轮换、登出与计数持同一把锁串行，多线程并发时标识不得重复、审计 seq 不得重号；快照深拷贝会话、审计与计数，恢复后取用与裁决结果和恢复前一致，非法快照整份拒绝且不动现有状态；全局会话数、单用户会话数、空闲时长都是硬顶。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发登录与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 其他
- type: Bugfix
- module: session_fixation_guard
- typeName: SessionFixationGuard
