# batch51-py-safety-c-35

## 题面

半月前安全评审在登录链路上复现了一个会话固定问题：站点已经改用 `__Host-sid` 下发会话，可下发响应里同时带着 `Domain=.example.com` 和 `Path=/v2`，浏览器按标准拒收这条 Cookie，前端只好回退到一条没有前缀的旧名字，攻击者抢注的同名 Cookie 于是被带上。另一头是网关自己的问题：同一个名字的 Cookie 从 a.example.com 和 b.example.com 各来一条，网关只按到达顺序保留最后一条，重放请求时选中的是范围更宽的那条；还有一条删除指令写成 `__Host-sid=; Max-Age=0`，运维以为已经删掉，实际上它一直被静默忽略。范围是 gsb/batch51-py-safety-c-35 下的 cookie_prefix_enforcer.py，类 CookiePrefixEnforcer，负责校验下发 Cookie 的属性组合、判断域覆盖并维护一份可投递集合。

公开接口：CookiePrefixEnforcer(*, max_cookies=16, secure_transport=True)；parse_set_cookie(header)；check_prefix(cookie)；scope_cover(cookie, host)；samesite_combo(cookie, *, cross_site=False)；apply(header, *, host, now=None)；deliver(host, path, *, secure=True)；name_count(name)；snapshot()；restore(state)；stats()。拒绝时抛 CookieError(code, detail)，code 为大写串。

要修的行为：① parse_set_cookie 解析 name=value 与 Path、Domain、Secure、HttpOnly、SameSite、Max-Age 六个属性，path 缺省 "/"，domain 去掉前导点并转小写、缺省为 None，samesite 转小写，max_age 转整数；空串、没有等号、属性值类型不对抛 COOKIE_HEADER_INVALID。② check_prefix 返回 {"ok","reason"}：`__Host-` 必须同时满足 Secure、Path 恰为 "/"、不带 Domain，缺 Secure 报 COOKIE_PREFIX_SECURE_REQUIRED，Path 不是 "/" 报 COOKIE_PREFIX_PATH_REQUIRED，带 Domain 报 COOKIE_PREFIX_DOMAIN_FORBIDDEN；`__Secure-` 必须有 Secure、允许带 Domain；其余名称直接通过。③ scope_cover 判域覆盖：带 Domain 的覆盖该域本身与全部子域，但不做后缀字符串匹配，notexample.com 与 example.com.evil.net 都不算；不带 Domain 的只覆盖 apply 时记下的来源主机，其子域不算。④ samesite_combo 返回 {"action","reason"}：未写 SameSite 按 lax 处理；SameSite=None 必须同时 Secure，否则 reject 并报 COOKIE_SAMESITE_NONE_INSECURE；取值不在 strict、lax、none 之内 reject 并报 COOKIE_SAMESITE_INVALID；cross_site 为真时 strict 与 lax 都 withhold 并报 COOKIE_SAMESITE_CROSS_SITE，none 且 Secure 照常 send。⑤ apply 依次做前缀校验、SameSite 校验、传输通道校验、同名取舍与容量校验，返回 {"accepted","reason","replaced","cookie"}，cookie 里带上 apply 时的来源主机。⑥ 通道本身不安全时，带安全前缀的 Cookie 即使写了 Secure 也拒收，reason 为 COOKIE_PREFIX_INSECURE_CHANNEL。⑦ 同名且同来源的 Cookie 只保留路径最长的一条：新路径更长则替换旧条并把 replaced 置真，路径不更长则拒收、reason 为 COOKIE_SHADOWED。⑧ 可投递集合硬顶 max_cookies，新增条目超限抛 COOKIE_JAR_LIMIT；替换已有条目不受容量限制。⑨ deliver 按来源主机、路径前缀与 Secure 过滤，按路径长度降序返回；secure 参数为假时不下发带 Secure 的 Cookie。⑩ name_count 返回某名字当前条目数，从未出现过的名字返回 0。⑪ snapshot 为 {"version","cookies","max_cookies","secure_transport","stats"}，cookies 是按写入顺序排列的列表；restore 遇字段缺失或类型不符抛 COOKIE_SNAPSHOT_INVALID 且原状态一字不动。⑫ stats 返回 applied、replaced、rejected、delivered、restores，delivered 累加每次返回的条数。

两处容易漏的判定单独说清：同名 Cookie 来自不同子域时按域长度判定覆盖关系，域更具体的那条优先，不得只按到达顺序保留最后一条；前缀约束同样作用于删除指令，值为空或 Max-Age 为 0 的下发也要过前缀校验，删除不满足前缀的组合不得被静默忽略。

硬约束：apply 与 deliver 并发时，一次投递要么看到写入前的完整集合要么看到写入后的完整集合，不能出现名字计数与条目数对不上的中间态；容量是硬顶，任何路径都不得越界写入；snapshot 必须深拷贝，restore 之后可投递集合、来源主机、路径与全部计数可往返，且恢复出的结构不与入参共享内存。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: cookie_prefix_enforcer
- typeName: CookiePrefixEnforcer
