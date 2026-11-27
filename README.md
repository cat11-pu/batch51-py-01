# batch51-py-safety-a-02

## 题面

改密页最近连续出事故：同一份泄露口令清单被反复外呼拉了十几遍，额度上午就打空，下午的改密请求要么全部放行要么全部拦死；还有租户在拿到命中结果之后仍把原口令写回了库。范围是 gsb/batch51-py-safety-a-02 的 breached_password_range_checker.py，类 BreachRangeChecker，用口令摘要前缀向外部区间接口取候选后缀并判定是否命中。

公开接口：BreachRangeChecker(*, fetcher, prefix_length=5, bucket_limit=64, cache_ttl=3600)；register_tenant(tenant, *, budget=10, offline_mode="block")；tenant_policy(tenant)；query_prefix(tenant, *, prefix, now)；check_password(tenant, *, digest, now)；submit_change(tenant, account, *, digest, now)；prewarm(tenant, prefixes)；budget_remaining(tenant)；reset_budget(tenant)；bucket_state(prefix)；purge_cache(now)；mark_login_failure(account)；mark_login_success(account)；login_locked(account)；snapshot()；restore(state)；stats()。fetcher 由调用方注入，形如前缀到后缀列表；时间参数为整数 epoch 秒。

要修的行为：① 摘要必须是十六进制且长于前缀，前缀统一转大写后查桶，非法摘要与非法前缀一律带原因码拒绝；② 冷启动首次查询必须真实外呼一次，回报来源（外呼、本地缓存、离线三种取值之一）、版本号、后缀条数与抓取时间，并扣掉该租户一次预算；③ 命中判拦截、未命中判放行，裁决里要带命中的前缀与桶版本，便于事后复盘；④ 同一前缀在有效期内重复查询只读本地，不再外呼也不再扣预算，过期后重新拉取并把桶版本抬高；⑤ 外部接口返回非字符串或非十六进制条目时，前缀查询按桶结构非法拒绝、不入缓存，口令检查按不可判定处理，不能当成未命中放过；⑥ 候选条目数超过分桶上限同样整桶丢弃并标不可判定，不许截断后取前若干条判未命中；⑦ 预算按租户独立计数，耗尽后立刻停止外呼；offline_mode 为 block 时判不可判定并拦截，为 allow 时判不可判定但放行；⑧ 裁决必须区分放行、拦截与不可判定三种结果，下游按 allowed 字段动作；⑨ 改密提交命中泄露口令必须拒绝，未命中则回受理成功并带成功原因码，且命中拒绝不得累加到该账号的登录失败次数上；⑩ 同一前缀的并发查询只能触发一次外呼，其余等待共享结果，预算只扣一次；⑪ 快照要能还原租户预算、桶缓存与登录失败计数，恢复后不共享可变结构，结构非法按原因码拒绝且不动现有数据；⑫ stats 至少给出外呼次数、缓存命中、预算耗尽、命中数、放行数与不可判定数六项计数。

工单里还有两个细节需要照顾：运维希望预热能在早高峰前把热门前缀一次拉好，事后只读本地；安全侧则要求任何一次命中都能追溯到具体前缀、桶版本与租户，不能只回一个布尔值。

硬约束：同前缀并发查询共享一次外呼且预算只扣一次；快照恢复后预算、桶版本与失败计数必须自洽；单桶条目数受 bucket_limit 硬顶，缓存按有效期清理不得无限增长。

验收：python3 -m pytest -q tests 15 条必须全过，不得改测试、不得跳过、不得按固定输入写死；并发与重启场景自行验证；只做本地实现，不引入第三方依赖。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 身份认证
- type: Bugfix
- module: breached_password_range_checker
- typeName: BreachRangeChecker
