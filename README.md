# batch51-py-safety-r-06

## 题面

上周聚合网关被一段查询打挂：客户端把同一个重字段用十几个别名包了一遍，单次请求的字段数翻了二十倍，执行器排队到超时；第二天又有人用两个互相引用的片段把展开逻辑卡死，进程内存一路涨到被系统杀掉；安全评审还发现，内省查询和正常业务查询共用一个额度，有人靠内省把整张 schema 抽走也没触发任何限流。现在查询必须先过准入器再进执行器。范围是 gsb/batch51-py-safety-r-06 的 graphql_cost_limiter.py，类 GraphqlCostLimiter，负责解析、片段展开、代价计算与限流裁决，并把拒绝原因写清楚。

公开接口：GraphqlCostLimiter(*, max_cost=1000, max_depth=10, max_aliases=25, introspection_budget=50)；parse(query)；resolve_fragments(document)；compute_depth(document)；compute_cost(document)；check_limits(document, *, client=None)；admit(query, *, client=None)；set_client_limits(client, *, max_cost=None, max_depth=None, max_aliases=None, introspection_budget=None)；client_limits(client)；clear_client_limits(client)；stats()；snapshot() 与 restore(state)。解析与结构问题抛 GraphqlError(code, detail)。

要修的故障与边界：①语法错误统一报 GRAPHQL_PARSE_ERROR，detail 带 offset；省略 query 关键字的花括号简写视为匿名查询，operation 仍是 query、name 为 None。②片段重名在解析阶段报 GRAPHQL_DUPLICATE_FRAGMENT，detail 为 {"name": 名}。③引用不存在的片段报 GRAPHQL_UNKNOWN_FRAGMENT，detail 为 {"name": 名}；片段之间成环必须报 GRAPHQL_FRAGMENT_CYCLE，detail 的 path 是首尾同名的片段名列表，不能只截断展开。④代价按展开后的字段出现次数累加，每个字段记 1，带别名的出现记 2，别名个数单独统计。⑤深度按选择集嵌套算，操作根下的字段深度为 1，内联片段与片段展开本身不加深度，展开后的字段按所在位置计深度。⑥超出 max_depth、max_cost、max_aliases 分别给出 GRAPHQL_DEPTH_EXCEEDED、GRAPHQL_COST_EXCEEDED、GRAPHQL_ALIAS_EXCEEDED 三种拒绝理由，判定顺序固定为深度、代价、别名、内省。⑦从 __schema 或 __type 起的内省子树整棵计入 introspection 配额，不占普通代价；__typename 仍按普通字段计 1。⑧同一片段被多个别名引用时只展开一次，但代价要按别名实例逐个累计，不能按片段定义去重。⑨指令条件为假的分支不计字段、代价、深度与别名，但语法上仍要参与片段环检测，不能因为分支被跳过就漏掉环。⑩字段数与深度解析后立刻算出，超过硬顶直接拒绝，不做截断执行，也不能靠展开缓存把深度算浅。⑪每个客户端可以覆盖全局额度，未登记的客户端沿用全局值；admit 才写统计，check_limits 只算不记。⑫快照保存全局额度、客户端覆盖与计数，恢复后同样的查询裁决结果与恢复前一致，非法快照整份拒绝且不动现有状态。

硬约束：解析、展开与计数在同一把锁下串行，多线程并发 admit 时解析数、放行数、拒绝数都不能丢计；深度与代价都有硬顶；快照恢复是原子的，失败不得留下半个客户端额度。

验收：`python3 -m pytest -q tests` 的 15 条用例全过，测试不得修改、跳过或按固定输入写死；并发裁决与快照恢复自行验证；只做本地实现。

## 运行方式

```bash
python3 -m pytest -q tests
```

## 平台字段

- domain: 安全
- sub: 其他
- type: Bugfix
- module: graphql_cost_limiter
- typeName: GraphqlCostLimiter
