# batch51-py-safety-b-04

## 题面

电商边缘节点这两天连续出 Cookie 事故：登录态在 www 能取到、在详情子域取不到；攻击者从不受信任的子域写入同名 Cookie，把主站会话顶掉；运维删一个旧 Cookie，同域其他路径的登录态也被一起打没了；代理侧日志还显示同一个会话名在三个子域各存了一份，回传优先级每次都不一样；把网关开关整体回滚后仍然复现，说明问题不在灰度入口。整改范围是 gsb/batch51-py-safety-b-04 下的 cookie_scope_guard.py，类型 CookieScopeGuard，为反向代理维护 Cookie 存储与下发、回传决策，非法请求抛 CookieScopeError(code, detail)。

公开接口：CookieScopeGuard(*, public_suffixes=("com", "net", "org"), max_cookies=200, max_per_domain=50)；store(set_cookie, origin_host, secure=True, now=None)；parse_set_cookie(set_cookie, origin_host, secure=True, now=None)；match(cookie, host, path, secure=True)；cookies_for(host, path, secure=True)；candidate_names(host, path, secure=True)；parse_cookie_header(header, host, path, secure=True)；get(name, domain, path)；clear(name, domain, path)；clear_domain(domain)；snapshot()；restore(state)；stats()。

故障与边界：①域名统一小写并去掉前导点、尾点，来源主机也先归一，判断时不做大小写敏感比较；Domain 属性必须与来源主机相同或为其父域，否则抛 COOKIE_DOMAIN_REJECTED，公共后缀上的 Domain 同样拒收；②Path 缺省为 /，匹配按段边界：/app 匹配 /app 与 /app/deep，不匹配 /application，路径末尾斜杠按同一段处理；③host-only 记录只在来源主机回传，带 Domain 的记录可覆盖其子域，写回时是否带前导点不影响匹配；④同名同域同路径覆盖时保留首次 created_at，只更新值与其他属性，覆盖不计 stored 也不计 rejected；⑤Max-Age 小于等于 0 或 Expires 已过期视为删除，命中已有记录返回 None 并计入 expired，删除不存在的记录返回 None 且不影响计数；⑥下发对象只含 name、value、domain、path、secure、http_only、same_site，内部字段如创建时间与前缀不外泄；⑦下发顺序按路径长度降序，长度相同再按创建时间升序，先创建的排前面；⑧__Secure- 前缀必须带 Secure 属性，否则抛 COOKIE_PREFIX_VIOLATION、整条拒收并计入 rejected，前缀名本身区分大小写；⑨__Host- 前缀缺 Secure、带 Domain 属性或 Path 不是 / 时必须整条拒收，不能降级为普通 Cookie；⑩每域条目数与总条目数都有硬顶，超限抛 COOKIE_STORE_FULL 并计入 rejected，覆盖已有键不占新额度；⑪clear 按 (name, domain, path) 精确删除并返回删除数，未命中返回 0，clear_domain 按域树级联删除该域及其子域，清理一个 Cookie 不能波及同域不同路径的其他记录；⑫父域设置的 Cookie 与子域同名时，子域请求的回传顺序必须让路径更具体者在前，宽度相同才按创建时间排序。

硬约束：并发写同一 (name, domain, path) 只能留一个生效版本，锁内完成比较与替换，created_at 不得回退；清理按域树级联，快照键固定为 version、cookies、stats，恢复后记录与计数一致、已删除的记录不得复活，且不与原结构共享引用；每域与总量都是硬顶，任何写入路径都不能越过。stats 返回 stored、replaced、rejected、cleared、expired。

验收：python3 -m pytest -q tests 15 条用例全过；不得改测试、跳过用例或按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: cookie_scope_guard
- typeName: CookieScopeGuard
