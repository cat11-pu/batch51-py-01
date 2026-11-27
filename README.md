# batch51-py-safety-b-03

## 题面

校园网准入网关这周被投诉：自习室的新设备连上网后能直接打开内网仓库，门户认证还没做完就漏了流量；一台机器刷下载把整段预认证通道拖到超时，用户刚认证成功又被踢回门户；门户日志里同一台设备几分钟内出现多条会话，配额各算各的，谁也说不清到底还剩多少。整改目标是 gsb/batch51-py-safety-b-03 下的 captive_portal_gate.py，类型 CaptivePortalGate，在客户端完成认证前只放行门户与白名单地址，其余请求拦截并记账，认证后切到正常放行，拒绝时抛 CaptiveError(code, detail)。

公开接口：CaptivePortalGate(*, session_ttl=600.0, byte_budget=1000000, max_sessions=128, portal_hosts=(), clock=None)；register_client(mac, addr, now=None)；complete_auth(mac, now=None)；authorize(mac, addr, host, now=None)；session_for(mac)；sessions()；consume_bytes(mac, count, now=None)；settle_expired(now=None)；update_allowlist(host, addresses, ttl=30.0, now=None)；allowlist_addresses(host, now=None)；snapshot()；restore(state)；stats()。

故障与边界：①硬件地址统一小写存储，register_client 建立 preauth 会话，返回对象含 mac、addr、state、started_at、expires_at、bytes_used、bytes_limit、authenticated_at，expires_at 等于 now 加 session_ttl，字节上限取构造参数；②空硬件地址、空地址、负预算、负扣减、非法会话时长抛 CAPTIVE_INVALID_ARGUMENT，构造参数非法同样报这个码；③未登记客户端访问非门户主机判 unregistered，访问 portal_hosts 内主机一律放行并记 portal，门户主机按名字精确比较；④预认证会话只放行白名单地址，其余判 blocked，白名单地址只在其有效窗口内生效；⑤consume_bytes 返回剩余额度，扣减不得越过上限，返回值不会为负，实际扣减累计进 bytes_consumed；⑥预认证额度用尽后即使目的地址合规也判 quota_exhausted，配额判定先于目的地址判定；⑦complete_auth 把会话置 authorized 并写 authenticated_at，之后任意主机按正常策略放行，未知硬件地址抛 CAPTIVE_UNKNOWN_CLIENT，已认证会话再调用不重复计数；⑧settle_expired 把 now 大于等于 expires_at 的预认证会话置 expired 并计数，已认证会话不受影响，过期后再授权判 expired，重复结算返回 0；⑨update_allowlist 按主机发布地址集合并返回当前集合，同一主机重复发布覆盖旧集合，allowlist_addresses 只返回窗口内有效地址；⑩预认证会话在认证成功的同一时刻到期，必须优先按认证成功处理并保留已建立连接，不能把用户踢回门户；⑪白名单域名解析出的地址发生变更后，旧地址要在短时间内失效而不是永久放行；⑫客户端更换地址但硬件地址不变时视为同一会话并沿用已消耗配额，地址相同而硬件地址不同则开新会话。

硬约束：并发认证与到期结算同时命中同一会话时只能留一种终态，锁内先判定认证成功再结算过期；预认证会话数不超过 max_sessions，单会话字节不超过 byte_budget，两者都是硬顶，超限不得静默截断已有会话；快照键固定为 version、sessions、allowlist、stats，恢复后会话、白名单、已消耗配额与计数一致且不与原结构共享引用。stats 返回 registered、authorized、allowed、denied、expired、bytes_consumed。

验收：python3 -m pytest -q tests 15 条用例全过；不得改测试、跳过用例或按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: captive_portal_gate
- typeName: CaptivePortalGate
