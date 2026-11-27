# batch51-py-safety-b-02

## 题面

递归解析集群最近被反射放大和 Cookie 重试风暴拖垮：部分来源每秒几千次不带客户端 Cookie 的查询，服务端 Cookie 轮换后旧缓存条目全被判非法，客户端拿着正确 Cookie 却一直收不到答复；监控里缺失计数和丢弃计数混在一起，值班同学分不清该限速还是该换密钥。整改范围是 gsb/batch51-py-safety-b-02 下的 dns_cookie_guard.py，类型 DnsCookieGuard，负责校验查询里的客户端与服务端 Cookie，产出答复、带新 Cookie 答复、要求重试、截断或丢弃，异常抛 DnsCookieError(code, detail)，错误码覆盖参数、快照与配额三类。

公开接口：DnsCookieGuard(secret, *, generation=1, overlap_generations=1, window=60.0, default_missing_budget=3, default_amplification_budget=4096)；client_cookie(source)；issue_server_cookie(source, generation=None)；verify(query_cookie, source, now=None)；rotate_key(now=None)；active_generations()；sweep(now=None)；set_source_policy(source, cookie_required=None, missing_budget=None, amplification_budget=None)；policy_for(source)；note_amplification(source, response_bytes, now=None)；quota_remaining(source, now=None)；snapshot()；restore(state)；stats()。

故障与边界：①客户端 Cookie 按来源确定性派生，16 位小写十六进制，派生结果只与来源和密钥有关，不随请求时间变化；服务端 Cookie 32 位，同来源同代次稳定，不同来源互不相同；②verify 的动作集合为 answer、answer_with_cookie、retry_with_cookie、truncate、drop，answer 不改写 Cookie 且 server_cookie 为 None，其余带 Cookie 的动作必须给出 32 位服务端 Cookie；③客户端 Cookie 必须恰为 16 位小写十六进制，完全缺失时返回 retry_with_cookie 并签发新服务端 Cookie，每次计入 missing_client，缺失配额在同一时间窗内按次扣减；④长度合法但值不符的客户端 Cookie 按伪造处理直接 drop，与缺失分开计数，不能占用缺失配额；⑤有正确客户端 Cookie 时，无服务端 Cookie 返回 answer_with_cookie 并签发，服务端 Cookie 属于活动代次则返回 answer；⑥rotate_key 递增代次，同一时刻重复调用只生效一次，换钥后签发默认用新代次，旧代次在重叠期内仍可校验；⑦sweep 按 overlap_generations 退役过旧代次并返回退役数量，退役代次的 Cookie 不再接受；⑧来源策略缺省 cookie_required=True、missing_budget=3、amplification_budget=4096，可单项覆盖，未覆盖项保留原值，空来源、负预算、过短密钥抛 DNS_COOKIE_INVALID_ARGUMENT；⑨note_amplification 扣减不越过预算并返回实际扣减数，quota_remaining 按时间窗恢复，窗口起点按该来源首次请求时间记录；⑩客户端 Cookie 长度不合法时按缺失处理并计入缺失配额，不能与伪造 Cookie 一样直接丢弃；⑪服务端 Cookie 校验失败但客户端 Cookie 正确时返回带新 Cookie 的答复，而不是静默丢弃让客户端反复重试；⑫同一来源放大配额用尽后即使 Cookie 正确也要降级为截断答复，配额恢复按时间窗而不是按请求数清零。

硬约束：并发换钥只允许一次生效，代次与活动代次列表不得丢更新；快照键固定为 version、generation、active、policies、windows、stats，恢复后策略、窗口与计数一致且不与原结构共享引用；每来源放大配额是硬顶，跨窗口只按时间重置，缺失配额与放大配额互不挪用。stats 返回 queries、answered、retried、dropped、truncated、missing_client、bad_server、rotations。

验收：python3 -m pytest -q tests 15 条用例全过；不得改测试、跳过用例或按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: dns_cookie_guard
- typeName: DnsCookieGuard
