# batch51-py-safety-c-23

## 题面

电商大促前一周，前端同事报过来一串互相矛盾的跨域故障：同一个接口在测试环境能带 Cookie 正常调用，上了预发就被浏览器拦掉；有人把来源列表里的通配项留着又开了凭证，页面时好时坏；还有一条路由改过来源之后，删掉的那条仍在生效，新加的那条反倒匹配不上。预发与生产的配置还是两份手抄的表格，每次改动都没人复核。范围是 gsb/batch51-py-safety-c-23 下的 cors_policy_evaluator_p2.py，类 CorsPolicyEvaluatorP2，按路由把来源、凭证与预检缓存时长一起算清楚。

公开接口：CorsPolicyEvaluatorP2(*, max_age_cap=600, default_max_age=120)；add_route(route_id, *, allow_origins, allow_credentials=False, max_age=None)；remove_route(route_id)；remove_origin(route_id, origin)；match_origin(route_id, origin)；check_credentials(route_id, origin, *, credentials)；preflight_ttl(route_id, *, requested_max_age=None)；evaluate(route_id, *, origin, method="GET", credentials=False)；describe_route(route_id)；list_routes()；snapshot()；restore(state)；stats()；reset()。拒绝时抛 CorsError(code, detail)。路由不存在时，查询与判定接口一律抛 CORS_UNKNOWN_ROUTE，detail 为路由标识。

要修的行为：① allow_origins 的每一项必须是字符串，空串、缺 scheme、带路径、星号位置不对都抛 CORS_INVALID_PATTERN，整条路由不落库；路由标识重复抛 CORS_DUPLICATE_ROUTE；② 重复模式去重后按首次出现顺序保留，add_route 返回去重后的条数；③ 精确模式与来源按小写比较，命中时返回配置里的模式串原样；④ 后缀模式 https://*.example.com 只匹配子域，主域本身和 scheme 不同的来源都不匹配；⑤ 多条模式同时命中取模式串最长者，长度相同精确模式优先；⑥ 无凭证请求命中 * 时回显 *，命中其他模式时回显具体来源；⑦ 带凭证但路由没开 allow_credentials 时拒绝，reason 为 credentials-not-allowed，echo_origin 为 None；⑧ 带凭证且命中的是 * 时拒绝，reason 为 wildcard-credentials，不得回显星号；⑨ 带凭证命中后缀模式时放行并回显具体来源，check_credentials 同步返回 True；⑩ 预检时长取路由配置，未配置用 default_max_age，再与请求值和 max_age_cap 取小，请求值为负数或非整数抛 CORS_INVALID_REQUEST；⑪ 来源为空值时按不匹配处理，即使配置里有 * 也不得放行；⑫ 删除某条来源后，剩余来源重新按最长优先排序，describe_route 给出新的顺序。

evaluate 返回 allowed、echo_origin、pattern、max_age、reason 五个字段，匹配不到时 reason 为 no-match、pattern 与 echo_origin 为 None，max_age 仍按路由给出预检值。describe_route 返回 route_id、allow_origins（按匹配优先级排序的元组）、allow_credentials、max_age 四个字段。list_routes 按标识升序返回；stats 返回 routes、evaluations、allowed、denied、preflights 五个计数；reset 清计数并保留路由与限额；快照里的路由按标识升序排列。

硬约束：同一个实例被多个线程同时 evaluate 与 remove_origin 时，单次判定只能看到改动前或改动后的完整配置，不得读到删了一半的来源表，计数不得丢；快照必须深拷贝，restore 后路由、凭证开关、限额与计数原样往返，结构不符抛 CORS_SNAPSHOT_INVALID 且原状态一字不动；预检时长以 max_age_cap 为硬顶，单条路由的来源条数同样有上限，任何路径都不能突破。

验收：`python3 -m pytest -q tests` 15 条全过；不得改测试、跳过、按固定输入写死；并发与快照自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 漏洞检测与攻防
- type: Bugfix
- module: cors_policy_evaluator_p2
- typeName: CorsPolicyEvaluatorP2
- file: cors_policy_evaluator_p2.py
