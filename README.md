# batch51-py-safety-b-05

## 题面

市场活动页上线后浏览器控制台全是跨源报错：带登录凭据的请求被回了一个星号，浏览器直接拒绝；某个接口只因为预检里多了一个自定义方法，整条路由的普通读取也一起 403；后端换端口灰度后，旧缓存里的预检结果还在生效，值班同学只能把缓存整段清空，灰度一回退又复发。整改范围是 gsb/batch51-py-safety-b-05 下的 cors_policy_evaluator.py，类型 CorsPolicyEvaluator，按路由与来源求值跨源策略，产出允许的来源、方法与头集合，并决定预检结果能否缓存，非法登记抛 CorsError(code, detail)。

公开接口：CorsPolicyEvaluator(*, max_cache_entries=64, default_max_age=600)；register_policy(route, origins, methods=("GET", "HEAD"), headers=(), allow_credentials=False, max_age=None)；policy_for(route)；evaluate(route, origin, method="GET", credentials=False, now=None)；preflight(route, origin, method, headers=(), credentials=False, now=None)；cache_key(route, origin, method, headers=())；remember(decision, now=None)；lookup_cache(key, now=None)；invalidate(route)；cache_size()；snapshot()；restore(state)；stats()。

故障与边界：①route 必须非空并原样保存，不做前缀补全，origins 不能为空且元素为非空字符串，methods 与 headers 的元素同样必须是非空字符串，methods 去重后转大写并保持首次出现顺序，headers 去重后转小写并保持首次出现顺序，max_age 缺省取 default_max_age；②来源按协议、主机、端口三段比较，缺省端口归一（https 的 443、http 的 80），主机名大小写归一后视为相同，不同端口视为不同来源；③精确来源命中返回具体来源，来源不匹配返回 origin-not-allowed，路由没有登记策略返回 no-policy 且 allow_origin 为 None，同样计一次 denied；④策略来源为通配且请求不带凭据时回星号；⑤请求带凭据要求策略 allow_credentials 为真，否则返回 credentials-not-allowed 且不给 allow_methods；⑥请求带凭据而策略来源为通配时，响应必须回显具体来源而不是返回通配，两者不能出现在同一条响应里；⑦preflight 依次校验来源、凭据、方法与头，方法不在策略内时只拒绝该方法，简单请求的读取仍按策略放行，不能整条路由失效；⑧preflight 声明的头不在策略内时返回 header-not-allowed，allowed 为 False 且 cacheable 为 False；⑨cache_key 由路由、归一后的来源、大写方法与排序去重后的头组成，头的顺序与大小写不影响结果，空头集合也要给出稳定键；⑩remember 只接受 cacheable 的决策，不可缓存的决策直接抛 CORS_INVALID_POLICY，缓存条目数不超过 max_cache_entries，超出时按最早写入淘汰并计 cache_evictions；⑪lookup_cache 未命中、已过期或所在路由被 invalidate 后返回 None，invalidate 返回删除条数，命中时返回的决策不能被调用方改动后影响存储；⑫快照键固定为 version、policies、cache、stats，非法结构抛 CORS_SNAPSHOT_INVALID 且原状态不变。

硬约束：策略登记与失效并发发生时以路由版本为准，旧预检缓存不得继续命中，锁内完成替换与清理；缓存条目数是硬顶，淘汰不得让 cache_size 超过上限；快照必须深拷贝，恢复后策略、缓存与计数一致且不与原结构共享引用。stats 返回 policies、evaluations、preflights、denied、cache_hits、cache_evictions。

验收：python3 -m pytest -q tests 15 条用例全过；不得改测试、跳过用例或按固定输入写死；并发与重启场景自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 网络与通信安全
- type: Bugfix
- module: cors_policy_evaluator
- typeName: CorsPolicyEvaluator
